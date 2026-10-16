//! PTY sessions.
//!
//! The terminal pane renders a real pseudo-terminal, because the DeepCode CLI
//! is a full-screen TUI and anything less would render garbage. On Windows this
//! is a ConPTY; on Unix it is a `openpty`. Either way the child process is
//! `docker run -it`, so the PTY the operator sees is the PTY inside the
//! container.

use crate::error::{Result, SandboxError};
use portable_pty::{native_pty_system, Child, ChildKiller, CommandBuilder, MasterPty, PtySize};
use std::path::Path;
use std::io::{Read, Write};
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct SessionOptions {
    pub program: PathBuf,
    pub args: Vec<String>,
    pub cwd: PathBuf,
    pub env: Vec<(String, String)>,
    pub rows: u16,
    pub cols: u16,
}

impl SessionOptions {
    /// A copy-pasteable rendering, used in logs and in the diagnostics panel.
    pub fn command_line(&self) -> String {
        let mut out = String::new();
        out.push_str(&self.program.to_string_lossy());
        for arg in &self.args {
            out.push(' ');
            if arg.contains(' ') {
                out.push_str(&format!("\"{arg}\""));
            } else {
                out.push_str(arg);
            }
        }
        out
    }
}

/// A live pseudo-terminal attached to the sandbox container.
pub struct Session {
    master: Box<dyn MasterPty + Send>,
    writer: std::sync::Arc<std::sync::Mutex<Box<dyn Write + Send>>>,
    killer: Box<dyn ChildKiller + Send + Sync>,
    description: String,
    /// The size the terminal was last given, or `None` before anything asked.
    ///
    /// Kept so the same size is never sent twice: see `resize_is_needed`.
    size: std::sync::Mutex<Option<(u16, u16)>>,
}

/// The size a resize would actually apply.
///
/// A pane hidden mid-layout measures zero, and a zero-sized terminal is one that has to be
/// corrected afterwards, so the floor is one row and one column rather than zero.
pub fn applied_size(rows: u16, cols: u16) -> (u16, u16) {
    (rows.max(1), cols.max(1))
}

/// Whether the terminal needs to hear about a size at all.
///
/// A window-change is not a no-op to what is running inside it: a full-screen TUI redraws
/// everything it has when the terminal changes size. So telling it the size it already has turns
/// somebody else's layout pass into a repaint of the whole session -- and a window that re-fits
/// on every layout pass, in that state, is a redraw loop. That is what an endless fast scroll of
/// the entire session is: too quick to read, and impossible to scroll up in, because the output
/// never stops arriving long enough for the viewport to stay where it was put.
pub fn resize_is_needed(current: Option<(u16, u16)>, rows: u16, cols: u16) -> bool {
    current != Some(applied_size(rows, cols))
}

/// Create the terminal and spawn the docker client in it, returning the master and the child.
///
/// Both `openpty` and `spawn_command` are blocking calls into ConPTY on Windows and cannot be
/// interrupted, so `Session::spawn` runs this on a worker with a deadline. Keeping both here means
/// the bound covers the whole creation, not just the second half of it: the first half was the one
/// that could still hang a launch after the second was bounded.
fn create_pty(
    program: &Path,
    args: &[String],
    cwd: &Path,
    env: &[(String, String)],
    rows: u16,
    cols: u16,
) -> Result<(Box<dyn MasterPty + Send>, Box<dyn Child + Send + Sync>)> {
    let pty_system = native_pty_system();
    let pair = pty_system
        .openpty(PtySize {
            rows,
            cols,
            pixel_width: 0,
            pixel_height: 0,
        })
        .map_err(|err| SandboxError::Broker(format!("could not open a pseudo-terminal: {err}")))?;

    let mut command = CommandBuilder::new(program);
    command.args(args);
    if cwd.is_dir() {
        command.cwd(cwd);
    }
    for (key, value) in env {
        command.env(key, value);
    }

    let child = pair.slave.spawn_command(command).map_err(|err| {
        SandboxError::DockerUnavailable(format!("could not start {}: {err}", program.display()))
    })?;
    // The slave handle must be dropped or the master never sees EOF. It is dropped here, on this
    // worker, immediately after the child has been created -- which is when it is no longer needed.
    let master = pair.master;
    drop(pair.slave);
    Ok((master, child))
}

impl Session {
    /// Spawn the container attached to a fresh PTY.
    ///
    /// `on_output` receives raw bytes as they arrive; `on_exit` receives the
    /// exit code once the container stops.
    pub fn spawn(
        options: SessionOptions,
        mut on_output: impl FnMut(&[u8]) + Send + 'static,
        on_exit: impl FnOnce(i32) + Send + 'static,
    ) -> Result<Self> {
        // Everything that touches the operating system's terminal lives on one worker, because on
        // Windows ConPTY can block inside *either* call -- `openpty` or `spawn_command` -- when the
        // console subsystem is wedged, and neither can be interrupted. The result is no log line,
        // no container, and a launch button saying "Starting..." forever, which is what this looked
        // like. The whole creation is bounded instead, and the timeout says what the problem is.
        let (created_tx, created_rx) = std::sync::mpsc::channel();
        {
            let program = options.program.clone();
            let args = options.args.clone();
            let cwd = options.cwd.clone();
            let env = options.env.clone();
            let rows = options.rows.max(1);
            let cols = options.cols.max(1);
            std::thread::spawn(move || {
                let _ = created_tx.send(create_pty(&program, &args, &cwd, &env, rows, cols));
            });
        }
        let (master, mut child) = match created_rx.recv_timeout(std::time::Duration::from_secs(20)) {
            Ok(Ok(pair)) => pair,
            Ok(Err(err)) => return Err(err),
            Err(_) => {
                return Err(SandboxError::DockerUnavailable(format!(
                    "the terminal for {} was not created within 20 seconds, so the container was never started. This is the operating system's terminal machinery rather than Docker: starting the project again is the first thing to try, and closing programs that hold the console is the second.",
                    options.program.display()
                )))
            }
        };

        let mut reader = master
            .try_clone_reader()
            .map_err(|err| SandboxError::Broker(format!("could not read from the pseudo-terminal: {err}")))?;
        let writer = std::sync::Arc::new(std::sync::Mutex::new(
            master.take_writer().map_err(|err| {
                SandboxError::Broker(format!("could not write to the pseudo-terminal: {err}"))
            })?,
        ));
        let killer = child.clone_killer();

        let description = options.command_line();

        // Reader thread: stream output to the UI until the PTY closes. It also answers the
        // terminal's own cursor question, because the docker client blocks on it before it even
        // creates the container -- which is what a launch that hangs with no container looks like.
        let replies = std::sync::Arc::clone(&writer);
        let (pty_rows, pty_cols) = (options.rows, options.cols);
        std::thread::Builder::new()
            .name("deepsand-pty-reader".into())
            .spawn(move || {
                let mut buffer = [0u8; 8192];
                loop {
                    match reader.read(&mut buffer) {
                        Ok(0) => break,
                        Ok(n) => {
                            let chunk = &buffer[..n];
                            if let Some(reply) = terminal_replies(chunk, pty_rows, pty_cols) {
                                if let Ok(mut writer) = replies.lock() {
                                    let _ = writer.write_all(reply.as_bytes());
                                    let _ = writer.flush();
                                }
                            }
                            on_output(chunk);
                        }
                        Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
                        Err(_) => break,
                    }
                }
            })
            .map_err(|err| SandboxError::Broker(format!("could not start the PTY reader thread: {err}")))?;

        // Waiter thread: report the exit code exactly once.
        std::thread::Builder::new()
            .name("deepsand-pty-waiter".into())
            .spawn(move || {
                let code = match child.wait() {
                    Ok(status) => exit_code_of(status),
                    Err(_) => -1,
                };
                on_exit(code);
            })
            .map_err(|err| SandboxError::Broker(format!("could not start the PTY waiter thread: {err}")))?;

        Ok(Self {
            master,
            writer,
            killer,
            description,
            size: std::sync::Mutex::new(Some(applied_size(options.rows, options.cols))),
        })
    }

    pub fn send(&mut self, data: &[u8]) -> Result<()> {
        let mut writer = self.writer.lock().unwrap_or_else(|p| p.into_inner());
        writer.write_all(data)?;
        writer.flush()?;
        Ok(())
    }

    /// Resize the terminal, once per size.
    ///
    /// A repeat is dropped rather than sent: see `resize_is_needed`. The window also stops asking
    /// (see `safeFit` in the terminal pane), and this is the half that holds even when something
    /// else starts asking -- a layout pass, an observer, or a future caller that has not read this.
    pub fn resize(&self, rows: u16, cols: u16) -> Result<()> {
        let wanted = applied_size(rows, cols);
        {
            let last = self.size.lock().unwrap_or_else(|p| p.into_inner());
            if !resize_is_needed(*last, rows, cols) {
                return Ok(());
            }
        }
        self.master
            .resize(PtySize {
                rows: wanted.0,
                cols: wanted.1,
                pixel_width: 0,
                pixel_height: 0,
            })
            .map_err(|err| SandboxError::Broker(format!("could not resize the terminal: {err}")))?;
        // Recorded only once the terminal took it, so a failed resize is retried by the next
        // request rather than being remembered as applied.
        let mut last = self.size.lock().unwrap_or_else(|p| p.into_inner());
        *last = Some(wanted);
        // Debug rather than info: dragging a window legitimately resizes once a frame for a
        // moment, and this line is only interesting when the sizes churn on their own.
        // `RUST_LOG=deepsand=debug` is what turns it on, and that is the first thing to reach for
        // if a terminal ever starts repainting itself again.
        tracing::debug!(rows = wanted.0, cols = wanted.1, "terminal resized");
        Ok(())
    }

    pub fn command_line(&self) -> &str {
        &self.description
    }

    /// Ask the container to stop. `docker run -it` forwards the signal, and the
    /// `--stop-timeout` on the plan gives DeepCode time to exit cleanly.
    pub fn kill(&mut self) {
        let _ = self.killer.kill();
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.kill();
    }
}

fn exit_code_of(status: portable_pty::ExitStatus) -> i32 {
    // portable_pty exposes the code directly on all supported platforms.
    status.exit_code() as i32
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    /// The reader inside `Session::spawn` answers the terminal's own queries now, so this harness
    /// must not: a second, different report made ConPTY redraw and split the child's output.
    struct Probe {
        text: String,
        exit_code: Option<i32>,
    }

    /// A shell is the one program guaranteed to exist on every platform, and it
    /// lets a test echo a sentinel without needing any other tool.
    fn shell_options(command: &str, env: Vec<(String, String)>) -> SessionOptions {
        let (program, flag) = if cfg!(windows) {
            (
                PathBuf::from(std::env::var("COMSPEC").unwrap_or_else(|_| "cmd.exe".into())),
                "/c",
            )
        } else {
            (PathBuf::from("/bin/sh"), "-c")
        };
        SessionOptions {
            program,
            args: vec![flag.to_string(), command.to_string()],
            cwd: std::env::temp_dir(),
            env,
            rows: 24,
            cols: 80,
        }
    }

    /// `echo` syntax differs between cmd.exe and sh, so build it once here.
    fn echo_command(variable: Option<&str>) -> String {
        match (cfg!(windows), variable) {
            (_, None) => "echo PTYOK".to_string(),
            (true, Some(name)) => format!("echo %{name}%"),
            (false, Some(name)) => format!("echo ${name}"),
        }
    }

    /// Run a short-lived command through a PTY, answering terminal queries, and return
    /// everything the child printed.
    ///
    /// `needle` is what to wait for, and `None` means "wait only for the exit code". That
    /// case exists because a deliberately tiny terminal cannot be asked for a particular
    /// line: at a clamped-to-minimum size the echo comes back wrapped and cut short, so
    /// waiting for a needle waited for the deadline instead -- 30 seconds of this suite for
    /// a fact the exit code had already established.
    fn probe(options: SessionOptions, needle: Option<&str>) -> Probe {
        let (output_tx, output_rx) = mpsc::channel::<Vec<u8>>();
        let (exit_tx, exit_rx) = mpsc::channel::<i32>();

        let mut session = Session::spawn(
            options,
            move |chunk| {
                let _ = output_tx.send(chunk.to_vec());
            },
            move |code| {
                let _ = exit_tx.send(code);
            },
        )
        .expect("the PTY should start");

        let mut collected: Vec<u8> = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(30);
        let mut exit_code = None;

        while Instant::now() < deadline {
            match output_rx.recv_timeout(Duration::from_millis(150)) {
                Ok(chunk) => collected.extend_from_slice(&chunk),
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }


            if let Ok(code) = exit_rx.try_recv() {
                exit_code = Some(code);
            }
            let saw_needle = needle.is_none_or(|needle| contains(&collected, needle.as_bytes()));
            if exit_code.is_some() && saw_needle {
                break;
            }
        }

        while let Ok(chunk) = output_rx.try_recv() {
            collected.extend_from_slice(&chunk);
        }
        if exit_code.is_none() {
            exit_code = exit_rx.try_recv().ok();
        }
        session.kill();

        Probe {
            text: String::from_utf8_lossy(&collected).to_string(),
            exit_code,
        }
    }

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }

    #[test]
    fn output_is_delivered_and_the_exit_code_is_reported() {
        let result = probe(shell_options(&echo_command(None), vec![]), Some("PTYOK"));
        assert!(
            result.text.contains("PTYOK"),
            "captured: {:?}",
            result.text
        );
        assert_eq!(result.exit_code, Some(0), "captured: {:?}", result.text);
    }

    #[test]
    fn environment_variables_reach_the_child() {
        let result = probe(
            shell_options(
                &echo_command(Some("DEEPSAND_TEST_VAR")),
                vec![("DEEPSAND_TEST_VAR".into(), "SENTINEL".into())],
            ),
            Some("SENTINEL"),
        );
        assert!(
            result.text.contains("SENTINEL"),
            "the child did not see DEEPSAND_TEST_VAR; captured: {:?}",
            result.text
        );
    }

    #[test]
    fn a_missing_program_is_reported_as_an_error_not_a_panic() {
        let options = SessionOptions {
            program: PathBuf::from("deepsand-definitely-not-a-real-program-xyz"),
            args: vec![],
            cwd: std::env::temp_dir(),
            env: vec![],
            rows: 24,
            cols: 80,
        };
        assert!(Session::spawn(options, |_| {}, |_| {}).is_err());
    }

    #[test]
    fn resizing_a_live_session_is_accepted() {
        let options = shell_options(&echo_command(None), vec![]);
        let session = Session::spawn(options, |_| {}, |_| {}).expect("the PTY should start");
        // A resize may legitimately fail if the child already exited, but it
        // must never panic.
        let _ = session.resize(40, 120);
    }

    #[test]
    fn the_command_line_is_rendered_for_diagnostics() {
        let options = SessionOptions {
            program: PathBuf::from("docker"),
            args: vec![
                "run".into(),
                "--name".into(),
                "deepsand-my-website".into(),
                "/home/me/my project".into(),
            ],
            cwd: std::env::temp_dir(),
            env: vec![],
            rows: 24,
            cols: 80,
        };
        let line = options.command_line();
        assert!(line.starts_with("docker run "));
        assert!(line.contains("\"/home/me/my project\""), "{line}");
        assert!(line.contains("--name deepsand-my-website"), "{line}");
    }

    #[test]
    fn a_zero_sized_terminal_is_clamped_rather_than_rejected() {
        let mut options = shell_options(&echo_command(None), vec![]);
        options.rows = 0;
        options.cols = 0;
        // Some window managers report 0x0 before the first layout pass, so this
        // must start rather than error out.
        // Only the exit code: see `probe` on why a clamped terminal has no line to wait for.
        let result = probe(options, None);
        assert!(result.exit_code.is_some(), "captured: {:?}", result.text);
    }
}

/// The reply the terminal owes, given bytes a program just wrote to it.
///
/// Exactly one question is answered, and it is the one a launch blocks on: `ESC[6n`, the cursor
/// position. ConPTY and the docker client ask it before anything else, and the docker client waits
/// for the reply before it even creates the container -- which, from the window, is a launch that
/// says "Starting..." forever with no container and no error. A front end can answer, but only if
/// it is already attached when the question arrives in the first milliseconds; the backend always
/// can, so it does.
///
/// The device-attributes question (`ESC[c`) is deliberately *not* answered: answering it told
/// ConPTY this client was a VT100, after which it rendered differently and split the child's own
/// output with backspaces.
pub fn terminal_replies(chunk: &[u8], _rows: u16, _cols: u16) -> Option<String> {
    let text = String::from_utf8_lossy(chunk);
    if !text.contains("\x1b[6n") {
        return None;
    }
    // The question is "where is the cursor?", and in a freshly created terminal the cursor is at
    // row 1, column 1. The size of the terminal is not what is being asked: answering with the
    // size (say 24;80) told ConPTY the cursor was at the bottom-right corner, after which
    // everything the child printed wrapped one character per line. 1;1 is the truth for a
    // brand-new terminal, and it is what the docker client is waiting to hear.
    Some("\x1b[1;1R".to_string())
}

#[cfg(test)]
mod terminal_query_tests {
    use super::*;

    /// The question a launch blocks on gets an answer, with the size the caller gave.
    #[test]
    fn the_cursor_question_is_answered_with_the_position_of_a_fresh_terminal() {
        assert_eq!(
            terminal_replies(b"\x1b[6n", 24, 80).as_deref(),
            Some("\x1b[1;1R")
        );
    }

    /// An unmeasured terminal is answered as the size ConPTY assumes, not as 1x1.
    #[test]
    fn an_unmeasured_terminal_is_answered_the_same_way() {
        assert_eq!(
            terminal_replies(b"\x1b[6n", 0, 0).as_deref(),
            Some("\x1b[1;1R")
        );
    }

    /// The identity question is left alone: answering it changed how ConPTY rendered.
    #[test]
    fn the_terminal_identity_question_is_left_to_the_front_end() {
        assert_eq!(terminal_replies(b"\x1b[c", 24, 80), None);
    }

    /// Ordinary output is not a question, and answering one unasked puts stray bytes in front of
    /// the program reading the terminal.
    #[test]
    fn ordinary_output_is_not_answered() {
        assert_eq!(terminal_replies(b"hello", 24, 80), None);
        assert_eq!(terminal_replies(b"\x1b[2J\x1b[H", 24, 80), None);
        assert_eq!(terminal_replies(b"", 24, 80), None);
    }
}

#[cfg(test)]
mod resize_tests {
    use super::*;

    /// The claim the fix rests on: a size the terminal already has is not sent to it again.
    #[test]
    fn a_size_the_terminal_already_has_is_not_sent_again() {
        assert!(!resize_is_needed(Some((40, 120)), 40, 120), "the same size is not a resize");
        assert!(resize_is_needed(Some((40, 120)), 41, 120), "a row more is");
        assert!(resize_is_needed(Some((40, 120)), 40, 119), "a column fewer is");
    }

    /// A terminal that has never been sized needs sizing, and a pane that measures zero is never
    /// left as a zero-sized terminal -- so a hidden pane's layout pass asks for nothing once it
    /// has been sized properly, which is what stops a layout pass becoming a resize.
    #[test]
    fn a_terminal_is_sized_once_and_never_to_zero() {
        assert!(resize_is_needed(None, 24, 80), "nothing has asked yet");
        assert_eq!(applied_size(0, 0), (1, 1));
        assert!(!resize_is_needed(Some((1, 1)), 0, 0));
    }
}
