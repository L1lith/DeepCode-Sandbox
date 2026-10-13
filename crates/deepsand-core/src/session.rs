//! PTY sessions.
//!
//! The terminal pane renders a real pseudo-terminal, because the DeepCode CLI
//! is a full-screen TUI and anything less would render garbage. On Windows this
//! is a ConPTY; on Unix it is a `openpty`. Either way the child process is
//! `docker run -it`, so the PTY the operator sees is the PTY inside the
//! container.

use crate::error::{Result, SandboxError};
use portable_pty::{native_pty_system, ChildKiller, CommandBuilder, MasterPty, PtySize};
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
        let pty_system = native_pty_system();
        let pair = pty_system
            .openpty(PtySize {
                rows: options.rows.max(1),
                cols: options.cols.max(1),
                pixel_width: 0,
                pixel_height: 0,
            })
            .map_err(|err| SandboxError::Broker(format!("could not open a pseudo-terminal: {err}")))?;

        let mut command = CommandBuilder::new(&options.program);
        command.args(&options.args);
        if options.cwd.is_dir() {
            command.cwd(&options.cwd);
        }
        for (key, value) in &options.env {
            command.env(key, value);
        }

        // Creating the pseudo-terminal is the last step before a container can exist, and on
        // Windows the console subsystem can block inside it: no log line, no container, and a
        // launch button that says "Starting..." until the window's own fifteen-minute watchdog
        // gives up. That is what a start hung here looks like from the outside, so the spawn runs
        // on a thread -- it is a blocking call that cannot be interrupted -- and waiting for it is
        // bounded. A wedged terminal is the operating system's doing, not Docker's, and the
        // message says so rather than blaming the daemon.
        let slave = pair.slave;
        let (spawned_tx, spawned_rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let outcome = slave.spawn_command(command);
            // Dropped on this thread: the slave handle has to go or the master never sees EOF.
            drop(slave);
            let _ = spawned_tx.send(outcome);
        });
        let mut child = match spawned_rx.recv_timeout(std::time::Duration::from_secs(20)) {
            Ok(Ok(child)) => child,
            Ok(Err(err)) => {
                return Err(SandboxError::DockerUnavailable(format!(
                    "could not start {}: {err}",
                    options.program.display()
                )))
            }
            Err(_) => {
                return Err(SandboxError::DockerUnavailable(format!(
                    "the terminal for {} was not created within 20 seconds, so the container was                      never started. This is the operating system's terminal machinery rather than                      Docker: starting the project again is the first thing to try, and closing                      programs that hold the console is the second.",
                    options.program.display()
                )))
            }
        };

        let mut reader = pair
            .master
            .try_clone_reader()
            .map_err(|err| SandboxError::Broker(format!("could not read from the pseudo-terminal: {err}")))?;
        // Shared, because two threads write here: the one forwarding the operator's keystrokes, and
        // the reader answering the terminal's own questions. `take_writer` hands out one handle, so
        // it goes round rather than being cloned.
        let writer = std::sync::Arc::new(std::sync::Mutex::new(
            pair.master.take_writer().map_err(|err| {
                SandboxError::Broker(format!("could not write to the pseudo-terminal: {err}"))
            })?,
        ));
        let killer = child.clone_killer();

        let description = options.command_line();

        // Reader thread: stream output to the UI until the PTY closes. It also answers the
        // terminal's own questions -- see `terminal_replies` -- because the program on the other end
        // is *blocked* until they are answered, and the question arrives long before a window can.
        let replies = std::sync::Arc::clone(&writer);
        let (pty_rows, pty_cols) = (options.rows.max(1), options.cols.max(1));
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
            master: pair.master,
            writer,
            killer,
            description,
        })
    }

    pub fn send(&mut self, data: &[u8]) -> Result<()> {
        let mut writer = self.writer.lock().unwrap_or_else(|p| p.into_inner());
        writer.write_all(data)?;
        writer.flush()?;
        Ok(())
    }

    pub fn resize(&self, rows: u16, cols: u16) -> Result<()> {
        self.master
            .resize(PtySize {
                rows: rows.max(1),
                cols: cols.max(1),
                pixel_width: 0,
                pixel_height: 0,
            })
            .map_err(|err| SandboxError::Broker(format!("could not resize the terminal: {err}")))
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

    /// ConPTY (and some Unix terminals) open by asking the terminal for its
    /// cursor position with `ESC[6n` and waiting for a reply. A real terminal
    /// answers; a bare pipe does not, and the child would stall forever.
    /// xterm.js in the app answers automatically, so the harness must too.
    const DEVICE_STATUS_REQUEST: &[u8] = b"\x1b[6n";
    const CURSOR_POSITION_REPORT: &[u8] = b"\x1b[1;1R";

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
            (_, None) => "echo deepsand-pty-ok".to_string(),
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
        let mut answered_dsr = false;
        let deadline = Instant::now() + Duration::from_secs(30);
        let mut exit_code = None;

        while Instant::now() < deadline {
            match output_rx.recv_timeout(Duration::from_millis(150)) {
                Ok(chunk) => collected.extend_from_slice(&chunk),
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }

            if !answered_dsr && contains(&collected, DEVICE_STATUS_REQUEST) {
                answered_dsr = true;
                let _ = session.send(CURSOR_POSITION_REPORT);
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
        let result = probe(shell_options(&echo_command(None), vec![]), Some("deepsand-pty-ok"));
        assert!(
            result.text.contains("deepsand-pty-ok"),
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
                vec![("DEEPSAND_TEST_VAR".into(), "sentinel-value".into())],
            ),
            Some("sentinel-value"),
        );
        assert!(
            result.text.contains("sentinel-value"),
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

/// The answers a terminal owes, given the bytes a program has just written to it.
///
/// Both of these are blocking questions, which is what makes them worth answering here rather than
/// leaving to a front end:
///
///  * `ESC[6n` -- "where is the cursor?" ConPTY and the docker client ask this on Windows before
///    anything else, and nothing continues until `ESC[<row>;<col>R` comes back. The window can
///    answer, but only if the question arrives after it has attached; this one arrives in the first
///    milliseconds, so nobody answers it and the launch sits there with no container and no log
///    line. That was a bug that looked exactly like a hung daemon.
///  * `ESC[c` -- "what kind of terminal are you?" A full-screen TUI asks before it draws anything,
///    and waits for the same reason.
///
/// The size is the one this terminal was created with, which is the truth as far as anything on the
/// other end can tell: the UI resizes it afterwards and reports that separately.
pub fn terminal_replies(chunk: &[u8], rows: u16, cols: u16) -> Option<String> {
    let text = String::from_utf8_lossy(chunk);
    let mut reply = String::new();
    if text.contains("\x1b[6n") {
        reply.push_str(&format!("\x1b[{};{}R", rows.max(1), cols.max(1)));
    }
    if text.contains("\x1b[c") || text.contains("\x1b[0c") {
        // A VT100 with advanced video, which is what everything expects to hear.
        reply.push_str("\x1b[?1;2c");
    }
    (!reply.is_empty()).then_some(reply)
}

#[cfg(test)]
mod terminal_query_tests {
    use super::*;

    /// The one that hung a launch: a cursor question gets an answer, with the size we were given.
    #[test]
    fn the_cursor_question_is_answered_with_the_size_of_this_terminal() {
        assert_eq!(
            terminal_replies(b"\x1b[6n", 24, 80).as_deref(),
            Some("\x1b[24;80R")
        );
    }

    /// And the question a TUI asks before it draws anything.
    #[test]
    fn the_terminal_identity_question_is_answered_too() {
        assert_eq!(
            terminal_replies(b"\x1b[c", 24, 80).as_deref(),
            Some("\x1b[?1;2c")
        );
    }

    /// Ordinary output is not a question, and answering one that was not asked would put stray
    /// characters in front of the program reading the terminal.
    #[test]
    fn ordinary_output_is_not_answered() {
        assert_eq!(terminal_replies(b"hello", 24, 80), None);
        assert_eq!(terminal_replies(b"\x1b[2J\x1b[H", 24, 80), None);
        assert_eq!(terminal_replies(b"", 24, 80), None);
    }
}
