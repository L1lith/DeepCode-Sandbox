//! A thin, argument-safe wrapper around the Docker CLI.
//!
//! Deepsand never builds a shell string. Every invocation is an explicit
//! argument vector, because a single shell in this path would be a
//! command-injection hole between the UI and the daemon.

use crate::error::{Result, SandboxError};
use crate::model::DockerStatus;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// Label applied to everything Deepsand creates, so orphan cleanup can be
/// precise and can never touch containers it did not create.
pub const LABEL_MANAGED: &str = "deepsand.managed=1";
pub const LABEL_PROJECT_PREFIX: &str = "deepsand.project=";

/// The result of a host-file-sharing preflight.
///
/// `ok` is the only thing callers should branch on; `detail` is written to be
/// shown to a human verbatim, because the underlying failure is otherwise
/// invisible.
#[derive(Debug, Clone)]
pub struct SharingCheck {
    pub ok: bool,
    pub detail: String,
}

impl SharingCheck {
    fn ok() -> Self {
        Self {
            ok: true,
            detail: "Files in this directory are readable inside a container.".to_string(),
        }
    }

    fn unavailable(detail: String) -> Self {
        Self { ok: false, detail }
    }
}

#[derive(Debug, Clone)]
pub struct Docker {
    program: PathBuf,
}

impl Docker {
    /// Find the Docker CLI. Prefers an explicit path, then `PATH`, then the
    /// well-known Docker Desktop install locations.
    pub fn locate() -> Result<Self> {
        if let Ok(explicit) = std::env::var("DEEPSAND_DOCKER") {
            let path = PathBuf::from(explicit);
            if path.exists() {
                return Ok(Self { program: path });
            }
        }

        let candidates: &[&str] = if cfg!(windows) {
            &[
                r"C:\Program Files\Docker\Docker\resources\bin\docker.exe",
                r"C:\ProgramData\DockerDesktop\version-bin\docker.exe",
            ]
        } else {
            &["/usr/bin/docker", "/usr/local/bin/docker", "/opt/homebrew/bin/docker", "/snap/bin/docker"]
        };

        for candidate in candidates {
            let path = PathBuf::from(candidate);
            if path.exists() {
                return Ok(Self { program: path });
            }
        }

        if let Some(found) = which("docker") {
            return Ok(Self { program: found });
        }

        Err(SandboxError::DockerUnavailable(
            "the `docker` command was not found. Install Docker Desktop (or Docker Engine on Linux) and make sure \
             it is running."
                .to_string(),
        ))
    }

    pub fn with_program(program: impl Into<PathBuf>) -> Self {
        Self { program: program.into() }
    }

    pub fn program(&self) -> &Path {
        &self.program
    }

    fn command(&self) -> Command {
        let mut cmd = Command::new(&self.program);
        // Never pop a console window when Deepsand runs as a GUI app on Windows.
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            const CREATE_NO_WINDOW: u32 = 0x0800_0000;
            cmd.creation_flags(CREATE_NO_WINDOW);
        }
        cmd.stdin(Stdio::null());
        cmd
    }

    /// How long one docker command may take before its process is ended.
    ///
    /// Everything that goes through here is short -- `inspect`, `ps`, `cp`, `exec` -- and none of
    /// it is the PTY, which has a lifetime of its own. Until this existed, `run_raw` waited with no
    /// limit at all: a docker CLI that never exits hung its caller forever, with no log line and no
    /// error, and a launch button sat on "Starting…" until the window's own fifteen-minute watchdog
    /// gave up. That is exactly what a wedged Docker Desktop produces, and the app had no way to say
    /// so. Bounded, a stuck command becomes a sentence that names it.
    pub const COMMAND_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);

    fn run_raw(&self, args: &[OsString]) -> Result<std::process::Output> {
        let mut cmd = self.command();
        cmd.args(args);
        let named = format!(
            "{} {}",
            self.program.display(),
            args.iter()
                .map(|arg| arg.to_string_lossy().to_string())
                .collect::<Vec<_>>()
                .join(" ")
        );
        wait_bounded(cmd, Self::COMMAND_TIMEOUT).map_err(|err| {
            if err.starts_with("could not start") {
                SandboxError::DockerUnavailable(format!(
                    "could not run {}: {err}. Is Docker Desktop running?",
                    self.program.display()
                ))
            } else {
                SandboxError::Docker {
                    command: named,
                    stderr: err,
                }
            }
        })
    }

    /// Run and return trimmed stdout, failing on a non-zero exit status.
    pub fn run(&self, args: &[String]) -> Result<String> {
        let os_args: Vec<OsString> = args.iter().map(OsString::from).collect();
        let output = self.run_raw(&os_args)?;
        if !output.status.success() {
            return Err(SandboxError::Docker {
                command: format!("{} {}", self.program.display(), args.join(" ")),
                stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
            });
        }
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    }

    /// Run, returning `None` instead of an error when the command fails.
    pub fn try_run(&self, args: &[String]) -> Option<String> {
        let os_args: Vec<OsString> = args.iter().map(OsString::from).collect();
        let output = self.run_raw(&os_args).ok()?;
        if !output.status.success() {
            return None;
        }
        Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
    }

    /// Run with a shorter leash than the full command timeout, returning `None` when the
    /// command fails *or does not finish in time*. This is for a check whose answer can safely
    /// default to "no": a resume is a convenience, so waiting the whole 120 seconds would be
    /// the hang the short leash exists to prevent.
    pub fn try_run_within(&self, args: &[String], limit: std::time::Duration) -> Option<String> {
        let mut cmd = self.command();
        let os_args: Vec<std::ffi::OsString> = args.iter().map(std::ffi::OsString::from).collect();
        cmd.args(&os_args);
        let output = wait_bounded(cmd, limit).ok()?;
        if !output.status.success() {
            return None;
        }
        Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
    }

    /// Start one throwaway container to learn whether the container runtime can start
    /// containers at all, returning what happened when it cannot.
    ///
    /// `docker version` and friends answer even while `docker run` hangs, so this is the only
    /// honest probe of the wedge. Two details matter, and both were wrong at first:
    ///
    ///   * The leash has to be long. The first container after Docker Desktop starts can take
    ///     ten seconds or more on a machine that has just booted, and a five-second limit
    ///     called that "not answering" -- refusing launches that would have worked a moment
    ///     later. Two attempts of twenty seconds each, because one slow answer is not a wedge.
    ///   * The image is only a vehicle. A probe against an image that does not exist yet fails
    ///     for a reason that has nothing to do with the runtime, so a missing image falls back
    ///     to any local one before any verdict is reached.
    pub fn runtime_check(&self, image: &str) -> std::result::Result<(), String> {
        let leash = std::time::Duration::from_secs(20);
        let candidate = if self.image_present(image) {
            image.to_string()
        } else {
            self.local_runtime_images()
                .into_iter()
                .next()
                .ok_or_else(|| "no runtime image exists to start a test container from".to_string())?
        };

        let args = self.fmt(&["run", "--rm", "--network=none", "--entrypoint=/bin/true", &candidate]);
        let mut last = format!("{candidate} did not start within {}s", leash.as_secs());
        for attempt in 1..=2 {
            if self.try_run_within(&args, leash).is_some() {
                return Ok(());
            }
            last = format!(
                "{candidate} did not start within {}s (attempt {attempt} of 2)",
                leash.as_secs()
            );
        }
        Err(last)
    }

    fn fmt(&self, args: &[&str]) -> Vec<String> {
        args.iter().map(|s| (*s).to_string()).collect()
    }

    /// Probe the installation: versions, whether it is Docker Desktop, and
    /// whether the runtime image is present.
    pub fn probe(&self, image: &str) -> DockerStatus {
        let mut status = DockerStatus::default();

        // Three calls, not five, and made at the same time.
        //
        // Every one of these spawns the Docker CLI, which costs 180-600 ms here -- measured:
        // 181 for `version`, 175 for the server version, 420 for one `info`, 588 for the
        // other, 185 for `image inspect`. Five of them in sequence is ~1.5 s, on a path the
        // app's first paint used to wait behind. `{{json .}}` returns everything the two
        // `version` calls and the two `info` calls were each asking for separately, and
        // `thread::scope` overlaps what is left, so the probe costs about as much as its
        // slowest call.
        let (version_json, info_json, image_id) = std::thread::scope(|scope| {
            let version = scope.spawn(|| self.try_run(&self.fmt(&["version", "--format", "{{json .}}"])));
            let info = scope.spawn(|| self.try_run(&self.fmt(&["info", "--format", "{{json .}}"])));
            let image = scope.spawn(|| self.image_id(image));
            (
                version.join().ok().flatten(),
                info.join().ok().flatten(),
                image.join().ok().flatten(),
            )
        });

        let (client, server) = version_json
            .as_deref()
            .map(parse_versions)
            .unwrap_or_default();
        status.client_version = client;
        match server {
            Some(version) if !version.is_empty() => {
                status.available = true;
                status.server_version = version;
            }
            _ => {
                // Asked only here: the extra call costs nothing on the path that matters, and
                // this is the one case where the answer changes what to say.
                status.detail = unreachable_detail(desktop_process_running()).to_string();
                return status;
            }
        }

        let (operating_system, name) = info_json.as_deref().map(parse_info).unwrap_or_default();
        status.operating_system = operating_system;
        status.desktop =
            status.operating_system.contains("Docker Desktop") || name.contains("docker-desktop");
        status.image_present = image_id.is_some();
        status.detail = if status.desktop {
            "Docker Desktop detected: the daemon runs inside a VM, so limited hardening options are available."
                .to_string()
        } else {
            String::new()
        };
        status
    }

    pub fn image_present(&self, tag: &str) -> bool {
        self.try_run(&self.fmt(&["image", "inspect", tag, "--format", "{{.Id}}"]))
            .is_some_and(|out| !out.is_empty())
    }

    /// The image's content id. Changes on every rebuild, which makes it the right key for
    /// caching a check that is only valid for one build of one image.
    pub fn image_id(&self, tag: &str) -> Option<String> {
        self.try_run(&self.fmt(&["image", "inspect", tag, "--format", "{{.Id}}"]))
            .filter(|id| !id.is_empty())
    }

    /// Read a file out of an image without starting a sandbox.
    ///
    /// This is how Deepsand fetches the digest the image carries for its seccomp profile:
    /// the file is inside the image, so reading it means running something, but the
    /// entrypoint is overridden so nothing from the image gets a say, and the network is
    /// off so the check cannot reach anything.
    pub fn read_file_from_image(&self, image: &str, path: &str) -> Result<String> {
        // Reading a file out of the image must not depend on the container runtime, so `docker
        // run` is not used: `docker create` only writes a container record (which even a wedged
        // daemon can do, as this machine has shown) and `docker cp` reads the image filesystem
        // directly. The seccomp verification is a launch preflight, so it must not inherit the
        // hang that `docker run` gets on a machine whose container runtime is wedged.
        let name = format!("deepsand-cat-{}", crate::now_ms());
        let probe = std::env::temp_dir().join(format!("deepsand-cat-{}-{}", std::process::id(), crate::now_ms()));
        let _ = self.try_run(&self.fmt(&["rm", "-f", &name]));
        let read = (|| -> Result<String> {
            self.run(&self.fmt(&["create", "--name", &name, image]))?;
            let mut cp_args = self.fmt(&["cp", "-"]);
            cp_args[1] = format!("{name}:{path}");
            cp_args.push(probe.display().to_string());
            self.run(&cp_args)?;
            std::fs::read_to_string(&probe).map_err(|err| {
                SandboxError::policy(format!("could not read {path} back out of the runtime image {image}: {err}"))
            })
        })();
        let _ = self.try_run(&self.fmt(&["rm", "-f", &name]));
        let _ = std::fs::remove_file(&probe);
        read.map_err(|err| match err {
            SandboxError::Docker { stderr, .. } => SandboxError::policy(format!(
                "could not read {path} out of the runtime image {image}: {stderr}"
            )),
            other => other,
        })
    }

    /// Stream a build, forwarding each output line to `sink`.
    /// Build the runtime image.
    ///
    /// `build_args` are passed as `--build-arg` pairs. They are how the tool
    /// selection reaches the image: the catalogue turns a selection into package
    /// lists and the Dockerfile installs them, so the two cannot disagree about what
    /// a project asked for.
    /// Whether the daemon's platform is `linux/amd64` or the like.
    ///
    /// The tool cache is keyed by it: a binary built for one will not run on the other.
    pub fn server_platform(&self) -> Option<String> {
        let out = self.try_run(&self.fmt(&["version", "--format", "{{.Server.Os}}/{{.Server.Arch}}"]))?;
        let out = out.trim().to_string();
        if out.is_empty() || out.starts_with('/') {
            None
        } else {
            Some(out)
        }
    }

    pub fn build(
        &self,
        context: &Path,
        tag: &str,
        build_args: &[(&str, String)],
        tool_cache: &Path,
        mut sink: impl FnMut(&str),
    ) -> Result<()> {
        let mut cmd = self.command();
        cmd.args([
            "build".as_ref(),
            "--tag".as_ref(),
            tag.as_ref(),
            "--file".as_ref(),
            context.join("Dockerfile").as_os_str(),
        ]);
        for (key, value) in build_args {
            cmd.arg("--build-arg");
            cmd.arg(format!("{key}={value}"));
        }
        // A named build context rather than a copy into the build context: a cache can be
        // hundreds of megabytes, and copying it per build would spend the time this exists to
        // save. It is passed even when empty -- the tools layer checks what is in it -- so the
        // instruction's mount always resolves.
        cmd.arg("--build-context");
        cmd.arg(format!("toolcache={}", tool_cache.display()));
        if let Some(extra) = std::env::var_os("DEEPSAND_BUILD_ARGS") {
            for part in extra.to_string_lossy().split_whitespace() {
                cmd.arg(part);
            }
        }
        cmd.arg(context.as_os_str());
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());

        let mut child = cmd.spawn().map_err(|err| {
            SandboxError::DockerUnavailable(format!("could not start `docker build`: {err}"))
        })?;

        use std::io::{BufRead, BufReader};

        // Both pipes are taken before the child is shared: the readers own the pipes and the
        // watchdog owns the child.
        let stdout = child.stdout.take().map(BufReader::new);
        let stderr_reader = child.stderr.take().map(BufReader::new);

        // The clock the watchdog reads, touched by every line whichever pipe it came from, and
        // the child itself, shared so the watchdog can end it without going near a pid.
        let quiet_since = std::sync::Arc::new(std::sync::Mutex::new(std::time::Instant::now()));
        let quiet_for_watchdog = std::sync::Arc::clone(&quiet_since);
        let child = std::sync::Arc::new(std::sync::Mutex::new(child));
        let child_for_watchdog = std::sync::Arc::clone(&child);

        // Whether the build ended because it went quiet, and whether someone asked for it to
        // stop. Both are read after the wait, to say which happened.
        let stopped_for_silence = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let cancelled = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let registered_pid = child
            .lock()
            .map(|child| child.id())
            .map_err(|_| SandboxError::policy("the build's handle was lost"))?;
        register_build(tag, registered_pid, &cancelled);

        // A build that stops talking is not going to finish. The readers below block on the
        // pipe, so nothing but the process ending can interrupt them -- and the app's own budget
        // for a build is half an hour, which is a long time to watch nothing happen.
        //
        // The first thing this checks is whether there is still a build to watch. It used to
        // `join()` instead, which meant a build that had *finished* still waited for the
        // watchdog to notice the silence that followed it -- ten minutes of a progress bar
        // frozen on the last step, which is exactly what it was written to prevent.
        let silence_flag = std::sync::Arc::clone(&stopped_for_silence);
        let watchdog = std::thread::spawn(move || {
            loop {
                std::thread::sleep(std::time::Duration::from_secs(5));
                let still_running = match child_for_watchdog.lock() {
                    Ok(mut child) => matches!(child.try_wait(), Ok(None)),
                    Err(_) => false,
                };
                if !still_running {
                    return;
                }
                let quiet = quiet_for_watchdog
                    .lock()
                    .map(|since| since.elapsed())
                    .unwrap_or_default();
                if !build_has_gone_quiet(quiet) {
                    continue;
                }
                tracing::warn!(
                    quiet_secs = quiet.as_secs(),
                    "the build has produced no output for {}s; stopping it",
                    quiet.as_secs()
                );
                silence_flag.store(true, std::sync::atomic::Ordering::SeqCst);
                if let Ok(mut child) = child_for_watchdog.lock() {
                    let _ = child.kill();
                }
                return;
            }
        });

        // Drain stdout on its own thread so a chatty build cannot deadlock
        // against the stderr reader.
        let drain = stdout.map(|reader| {
            std::thread::spawn(move || {
                let mut collected = Vec::new();
                for line in reader.lines().map_while(std::result::Result::ok) {
                    collected.push(line);
                }
                collected
            })
        });

        // Keep the last lines so a failure can say what actually went wrong. The error
        // used to read "the build failed; see the build log above", and the log lives in
        // the UI's memory and dies with the window: an operator pasted exactly that
        // sentence into a bug report and the one line that mattered -- apt refusing a
        // comma-separated package list -- was gone.
        let mut tail: Vec<String> = Vec::new();
        let keep_tail = |line: &str, tail: &mut Vec<String>| {
            if tail.len() == BUILD_TAIL_LINES {
                tail.remove(0);
            }
            tail.push(line.to_string());
        };
        // Every line goes through the filter, so none of this reaches the tail, the emit or
        // the log: the log file is the artifact a human reads after a failure, and it is the
        // one that was filled with NULs by a daemon that vanished mid-build.
        let mut sink = |line: &str| {
            let Some(line) = sanitize_output_line(line) else {
                return;
            };
            if let Ok(mut since) = quiet_since.lock() {
                *since = std::time::Instant::now();
            }
            keep_tail(&line, &mut tail);
            sink(&line);
        };

        if let Some(reader) = stderr_reader {
            for line in reader.lines().map_while(std::result::Result::ok) {
                sink(&line);
            }
        }
        if let Some(handle) = drain {
            if let Ok(lines) = handle.join() {
                for line in lines {
                    sink(&line);
                }
            }
        }

        let status = child
            .lock()
            .map_err(|_| SandboxError::policy("the build's handle was lost"))?
            .wait()?;
        unregister_build(tag);
        // The watchdog is left to notice that the build it was watching is over; joining it
        // here would block this build on the *next* thing the watchdog checks, which is how a
        // finished build sat for ten minutes with its progress bar frozen.
        drop(watchdog);

        let was_cancelled = cancelled.load(std::sync::atomic::Ordering::SeqCst);
        if was_cancelled {
            return Err(SandboxError::Docker {
                command: format!("docker build -t {tag} {}", context.display()),
                stderr: format!(
                    "the build was stopped. Nothing is wrong with the image files, and starting \
                     it again carries on from the steps that had already finished.\n\n{}",
                    describe_build_failure(&tail)
                ),
            });
        }
        if stopped_for_silence.load(std::sync::atomic::Ordering::SeqCst) {
            // A fact rather than a diagnosis: it produced nothing for the limit, so it was
            // stopped. Whatever it did say is in the log and in the tail below.
            return Err(SandboxError::Docker {
                command: format!("docker build -t {tag} {}", context.display()),
                stderr: format!(
                    "the build produced no output for {} minutes, so it was stopped. Its output \
                     up to that point is in the build log. The step it was on is the last line \
                     of it, and starting the build again resumes from the steps that finished.\n\n{}",
                    BUILD_SILENCE_LIMIT.as_secs() / 60,
                    describe_build_failure(&tail)
                ),
            });
        }
        if !status.success() {
            return Err(SandboxError::Docker {
                command: format!("docker build -t {tag} {}", context.display()),
                stderr: describe_build_failure(&tail),
            });
        }
        Ok(())
    }

    /// Copy a directory's contents into a running container.
    ///
    /// A trailing `.` on the source is what makes this copy the *contents* rather than the
    /// directory itself: `/usr/local/bin/.` lands in `/usr/local/bin`, while `/usr/local/bin`
    /// would land in `/usr/local/bin/bin`. That distinction is the difference between a tool
    /// being on `PATH` and being invisible.
    ///
    /// `docker cp` rather than a mount because the container is already running and its mounts
    /// were fixed when it started.
    pub fn copy_into_container(&self, container: &str, from: &Path, to: &str) -> Result<()> {
        let source = format!("{}{}.", from.display(), std::path::MAIN_SEPARATOR);
        self.run(&self.fmt(&["cp", &source, &format!("{container}:{to}")]))?;
        Ok(())
    }

    pub fn volume_create(&self, name: &str) -> Result<()> {
        if self
            .try_run(&self.fmt(&["volume", "inspect", name, "--format", "{{.Name}}"]))
            .is_some_and(|out| !out.is_empty())
        {
            return Ok(());
        }
        self.run(&self.fmt(&[
            "volume",
            "create",
            "--label",
            LABEL_MANAGED,
            name,
        ]))
        .map(|_| ())
    }

    pub fn volume_remove(&self, name: &str) {
        let _ = self.try_run(&self.fmt(&["volume", "rm", name]));
    }

    pub fn volume_exists(&self, name: &str) -> bool {
        self.try_run(&self.fmt(&["volume", "inspect", name, "--format", "{{.Name}}"]))
            .is_some_and(|out| out == name)
    }

    /// Does the sandbox's session volume already hold a DeepCode session index?
    ///
    /// This matters because `deepcode --last` calls `process.exit(1)` with
    /// "No previous sessions found for the current project." when the index is
    /// missing, so resuming has to be *verified* rather than assumed. The probe
    /// is a throwaway container with the sandbox's restrictions minus the
    /// network, running a fixed argument vector with no interpolated shell.
    /// Write `contents` to `path` inside a running container.
    ///
    /// Used to change a setting on a sandbox that is already running: the file lives
    /// in the container's named volume, which the host cannot address as a path, so
    /// it is written through `docker exec` with the bytes on stdin rather than by
    /// building a command string.
    ///
    /// The chown is best-effort: the exec runs as root, but the sandboxed process is
    /// uid 1000 and has to be able to rewrite the file itself.
    pub fn write_into_container(&self, container: &str, path: &str, contents: &[u8]) -> Result<()> {
        let mut cmd = self.command();
        // Chained `arg` rather than an array: the destination path is passed as `$1`
        // to `sh` rather than interpolated into the script, so a path with a quote or
        // a space in it cannot become part of the command.
        cmd.arg("exec")
            .arg("-i")
            .arg(container)
            .arg("sh")
            .arg("-c")
            .arg("cat > \"$1\" && chown 1000:1000 \"$1\" 2>/dev/null || true")
            .arg("sh")
            .arg(path);
        cmd.stdin(std::process::Stdio::piped());
        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::piped());

        let mut child = cmd.spawn().map_err(|err| SandboxError::Docker {
            command: "docker exec".into(),
            stderr: err.to_string(),
        })?;
        {
            use std::io::Write as _;
            let mut stdin = child.stdin.take().ok_or_else(|| SandboxError::Docker {
                command: "docker exec".into(),
                stderr: "could not open the container's stdin".into(),
            })?;
            stdin.write_all(contents).map_err(|err| SandboxError::Docker {
                command: "docker exec".into(),
                stderr: format!("could not write into the container: {err}"),
            })?;
            // Dropped here, which closes the pipe and lets `cat` finish.
        }
        let output = child.wait_with_output().map_err(|err| SandboxError::Docker {
            command: "docker exec".into(),
            stderr: err.to_string(),
        })?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(SandboxError::Docker {
                command: "docker exec".into(),
                stderr: format!("could not write {path} in the running sandbox: {}", stderr.trim()),
            });
        }
        Ok(())
    }

    /// Create a directory inside a running container, parents and all.
    ///
    /// `write_into_container` writes with `cat >`, which cannot create the directory it writes
    /// into, so anything that needs a new one asks for this first. Ownership is the sandbox
    /// user's, so the agent can read and replace what it is given.
    pub fn make_dirs_in_container(&self, container: &str, path: &str) -> Result<()> {
        let mut cmd = self.command();
        // The same shape as the write above: the path goes in as `$1` rather than into the
        // script, so a quote or a space in it cannot become part of a command.
        cmd.arg("exec")
            .arg(container)
            .arg("sh")
            .arg("-c")
            .arg("mkdir -p \"$1\" && chown 1000:1000 \"$1\" 2>/dev/null || true")
            .arg("sh")
            .arg(path);
        let output = cmd.output().map_err(|err| SandboxError::Docker {
            command: "docker exec".into(),
            stderr: err.to_string(),
        })?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(SandboxError::Docker {
                command: "docker exec".into(),
                stderr: format!("could not create {path} in the running sandbox: {}", stderr.trim()),
            });
        }
        Ok(())
    }

    pub fn volume_has_session_index(&self, volume: &str, image: &str) -> bool {
        if !self.volume_exists(volume) {
            return false;
        }
        let mut args = self.fmt(&[
            "run",
            "--rm",
            "--network=none",
            "--read-only",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--user=0:0",
            "--entrypoint=/usr/bin/find",
            "-v",
        ]);
        args.push(format!("{volume}:/deepsand-probe:ro"));
        args.push(image.to_string());
        for arg in ["/deepsand-probe", "-name", "sessions-index.json", "-print", "-quit"] {
            args.push(arg.to_string());
        }

        self.try_run_within(&args, std::time::Duration::from_secs(10))
            .is_some_and(|out| out.contains("sessions-index.json"))
    }

    /// Verify that a host directory really can be bind-mounted *and read*.
    ///
    /// This exists because the failure mode is silent and deeply confusing.
    /// Docker Desktop only shares directories listed under
    /// Settings -> Resources -> File Sharing. When a path is not shared, or the
    /// file-sharing service is misbehaving, the bind mount does not fail: the
    /// directory appears inside the container, but every entry in it appears as a
    /// zero-length *directory*. `ls` shows the names, so the mount looks fine,
    /// yet no file's contents can be read.
    ///
    /// Since the project directory is always bind-mounted, that would make
    /// Deepsand look broken rather than misconfigured. So a probe file is written
    /// on the host and read back from inside a container, and the answer is a
    /// plain-language verdict instead of a mystery.
    pub fn check_host_sharing(&self, dir: &Path, image: &str) -> SharingCheck {
        let token = format!("deepsand-sharing-probe-{}", crate::now_ms());
        let probe = dir.join(&token);

        if let Err(err) = std::fs::write(&probe, &token) {
            return SharingCheck::unavailable(format!(
                "Deepsand could not write a probe file into {} ({err}). The project directory has to be \
                 writable by your own account before it can be shared with a container.",
                dir.display()
            ));
        }

        // The probe answers one question -- can a container read this host directory? -- so it is
        // run against whichever image can answer it. The image the plan would use is tried first,
        // but an image that has not been built yet is not a reason to fail: docker would try to
        // pull it and report "pull access denied", which says nothing about the mount. A local
        // runtime image answers just as well.
        let attempt = |image: &str| -> crate::Result<String> {
            let mut args = self.fmt(&[
                "run",
                "--rm",
                "--network=none",
                "--read-only",
                "--cap-drop=ALL",
                "--security-opt=no-new-privileges",
                "--user=0:0",
                "--entrypoint=/bin/cat",
                "-v",
            ]);
            args.push(format!("{}:/deepsand-probe:ro", dir.display()));
            args.push(image.to_string());
            args.push(format!("/deepsand-probe/{token}"));
            // The short leash matters: when the container runtime is wedged, a probe that waits
            // the whole command timeout is exactly the launch hang this preflight is meant to
            // prevent. Fifteen seconds is far more than a healthy cat needs, and when it is not
            // enough the message says so instead of pretending the mount is broken.
            self.try_run_within(&args, std::time::Duration::from_secs(15))
                .ok_or_else(|| SandboxError::policy(
                    "the probe did not finish in 15 seconds; Docker's container runtime is not answering",
                ))
        };

        let candidates: Vec<String> = std::iter::once(image.to_string())
            .chain(
                self.local_runtime_images()
                    .into_iter()
                    .filter(|tag| tag != image)
                    .take(1),
            )
            .collect();

        let mut last_detail = String::from("no image was available to run the probe");
        for candidate in &candidates {
            match attempt(candidate) {
                Ok(out) if out.contains(&token) => {
                    let _ = std::fs::remove_file(&probe);
                    return SharingCheck::ok();
                }
                Ok(out) => {
                    last_detail = format!(
                        "the probe ran on {candidate} but did not return its token ({out:?})"
                    )
                }
                Err(err) => {
                    last_detail = format!("running the probe on {candidate} failed: {err}")
                }
            }
        }
        let _ = std::fs::remove_file(&probe);

        let advice = if last_detail.contains("not answering") || last_detail.contains("not finish") {
            "Docker's container runtime is not answering. Restart Docker Desktop, then try again."
        } else {
            "On Docker Desktop, add the drive that holds your projects under Settings -> Resources \
             -> File Sharing, choose Apply & Restart, then try again. On Linux, check that the path \
             is visible to the daemon."
        };
        SharingCheck::unavailable(format!(
            "Docker could not read a probe file from {} inside a container, so a bind mount would \
             look like an empty directory to DeepCode.\n\n{advice}\n\nDocker itself said: {last_detail}",
            dir.display()
        ))
    }

    /// Every local runtime image, newest first.
    ///
    /// The sharing probe can run on any of them; a plan whose image has not been built yet must
    /// not turn "image missing" into "the mount is unreadable".
    fn local_runtime_images(&self) -> Vec<String> {
        let mut found: Vec<(String, String)> = self
            .try_run(&self.fmt(&["images", "--format", "{{.CreatedAt}}\t{{.Repository}}:{{.Tag}}"]))
            .unwrap_or_default()
            .lines()
            .filter_map(|line| line.split_once('\t'))
            .filter(|(_, tag)| tag.starts_with("deepsand/runtime:"))
            .map(|(when, tag)| (when.to_string(), tag.to_string()))
            .collect();
        found.sort_by(|a, b| b.0.cmp(&a.0));
        found.into_iter().map(|(_, tag)| tag).collect()
    }

    /// Create the per-project bridge network used by the restricted egress mode.
    pub fn network_ensure(&self, name: &str) -> Result<String> {
        if let Some(gateway) = self.network_gateway(name) {
            return Ok(gateway);
        }
        let _ = self.try_run(&self.fmt(&["network", "create", "--label", LABEL_MANAGED, name]));
        self.network_gateway(name).ok_or_else(|| SandboxError::Docker {
            command: format!("docker network create {name}"),
            stderr: "the network was created but no gateway address could be read back".to_string(),
        })
    }

    pub fn network_gateway(&self, name: &str) -> Option<String> {
        let gateway = self.try_run(&self.fmt(&[
            "network",
            "inspect",
            name,
            "--format",
            "{{range .IPAM.Config}}{{.Gateway}}{{end}}",
        ]))?;
        if gateway.is_empty() {
            None
        } else {
            Some(gateway)
        }
    }

    pub fn network_remove(&self, name: &str) {
        let _ = self.try_run(&self.fmt(&["network", "rm", name]));
    }

    /// One label's value on an *image*, or `None` if it cannot be read.
    ///
    /// Used to ask an image what it was built with rather than inferring it from the
    /// settings that requested the build. Those can have changed since, and a snapshot
    /// that contradicts the image is worse than no snapshot.
    pub fn image_label(&self, tag: &str, key: &str) -> Option<String> {
        let template = format!("{{{{index .Config.Labels \"{key}\"}}}}");
        let out = self.try_run(&self.fmt(&["image", "inspect", "-f", &template, tag]))?;
        let out = out.trim().to_string();
        if out.is_empty() || out == "<no value>" {
            None
        } else {
            Some(out)
        }
    }

    /// One label's value on a container, or `None` if it does not exist or lacks it.
    ///
    /// `index` rather than a dotted path, because a missing label then yields
    /// `<no value>` instead of a template error, which is what makes "does this
    /// container carry our marker" answerable without a second call.
    pub fn container_label(&self, name: &str, key: &str) -> Option<String> {
        let template = format!("{{{{index .Config.Labels \"{key}\"}}}}");
        let out = self.try_run(&self.fmt(&["inspect", "-f", &template, name]))?;
        let out = out.trim().to_string();
        if out.is_empty() || out == "<no value>" {
            None
        } else {
            Some(out)
        }
    }

    /// A one-line description of a container's state, or `None` if it does not exist.
    ///
    /// Used in the message the operator sees when a stale container is cleared, so the
    /// message can say what was cleared rather than just that something was.
    pub fn container_summary(&self, name: &str) -> Option<String> {
        let out = self.try_run(&self.fmt(&["inspect", "-f", "{{.State.Status}} {{.Id}}", name]))?;
        let mut parts = out.split_whitespace();
        let status = parts.next().unwrap_or("unknown");
        let id = parts.next().unwrap_or("");
        let short = &id[..id.len().min(12)];
        if short.is_empty() {
            Some(status.to_string())
        } else {
            Some(format!("{status}, {short}"))
        }
    }

    /// Free a container name, returning a description of what was holding it.
    ///
    /// Called immediately before `docker run`, because a name that is still held is a
    /// failure the operator cannot act on: they asked to run the project, and the
    /// answer "that name is in use" tells them nothing they can do about it.
    pub fn reclaim_container_name(&self, name: &str) -> Option<String> {
        let summary = self.container_summary(name)?;
        self.remove_container(name);
        Some(summary)
    }

    /// Force-remove a container by name. Safe to call when it does not exist.
    pub fn remove_container(&self, name: &str) {
        let _ = self.try_run(&self.fmt(&["rm", "-f", "-v", name]));
    }

    pub fn container_running(&self, name: &str) -> bool {
        self.try_run(&self.fmt(&["inspect", "-f", "{{.State.Running}}", name]))
            .is_some_and(|out| out == "true")
    }

    /// Every container Deepsand has created, by name.
    pub fn managed_containers(&self) -> Vec<String> {
        self.try_run(&self.fmt(&[
            "ps",
            "-a",
            "--filter",
            &format!("label={LABEL_MANAGED}"),
            "--format",
            "{{.Names}}",
        ]))
        .map(|out| out.lines().map(str::trim).filter(|l| !l.is_empty()).map(str::to_string).collect())
        .unwrap_or_default()
    }

    /// Remove managed containers for projects that no longer exist.
    pub fn prune_orphans(&self, keep: &[String]) -> Vec<String> {
        let mut removed = Vec::new();
        for name in self.managed_containers() {
            if !keep.iter().any(|k| k == &name) {
                self.remove_container(&name);
                removed.push(name);
            }
        }
        removed
    }
}

/// The build step a line reports, if it reports one.
///
/// BuildKit writes `#7 [4/23] RUN …`; the classic builder writes `Step 4/23 : RUN …`.
/// Both are the same information, and it is the only progress a Docker build reliably
/// exposes -- there is no percentage, and the log is not proportional to the work.
///
/// Returns `None` rather than a guess when a line reports nothing, so a caller can show
/// an indeterminate bar instead of a fabricated number.
/// How many lines of build output a failure carries. Enough for the failing step's own
/// message and its last line of context; not so many that the toast is a wall of text.
/// What to tell the operator when the daemon does not answer.
///
/// The daemon and the Docker Desktop application are not the same thing. The window can be up
/// with every one of its processes running -- `Docker Desktop.exe`, `com.docker.backend.exe`,
/// `com.docker.build.exe` -- while the daemon behind it answers nothing, which is a state this
/// machine spends real time in. Telling somebody to start what they can see running is how a
/// correct message gets ignored, so the two cases say different things.
pub fn unreachable_detail(desktop_running: bool) -> &'static str {
    if desktop_running {
        "Docker Desktop is running, but its daemon is not answering. It can take a minute to come \
         up after starting; if it stays like this, restart Docker Desktop."
    } else {
        "Docker Desktop is not running. Start it and try again."
    }
}

/// Whether the Docker Desktop application is running, asked only when the daemon did not answer.
///
/// Windows and macOS only, and deliberately forgiving: a check that cannot run says "not
/// running", which is the message that was there before this existed.
fn desktop_process_running() -> bool {
    #[cfg(windows)]
    {
        let mut command = std::process::Command::new("tasklist");
        command.args(["/FI", "IMAGENAME eq Docker Desktop.exe", "/NH"]);
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        command.creation_flags(CREATE_NO_WINDOW);
        // `tasklist` exits 0 whether or not the task exists, and says so in the output, so this
        // looks for the image name rather than for success.
        return command
            .output()
            .map(|out| String::from_utf8_lossy(&out.stdout).contains("Docker Desktop.exe"))
            .unwrap_or(false);
    }
    #[cfg(target_os = "macos")]
    {
        return std::process::Command::new("pgrep")
            .args(["-x", "Docker Desktop"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|status| status.success())
            .unwrap_or(false);
    }
    #[allow(unreachable_code)]
    false
}

/// The client and server versions out of `docker version --format '{{json .}}'`.
///
/// A daemon that is not running still prints a `Client` block, and may omit `Server` or
/// report it as null, so the server half is optional rather than an error: the caller turns
/// its absence into "the daemon is not reachable".
/// One line of build output, or `None` if it is not text at all.
///
/// A read from a dying Docker daemon's pipe can come back **zero-filled**: the reader gets
/// its whole buffer length in NULs and no newline, so `lines()` hands back one "line" of
/// 32 KiB of nothing. That was written to the build log as content, and the log from the
/// failure this comes from is 302 bytes of real output followed by 32,289 NULs -- a file
/// 32,767 bytes long that had five lines to say. Anything after the first NUL is not text,
/// so it is dropped, and a line that is only that is dropped entirely.
///
/// Long lines are truncated rather than trusted: no build step writes a 4 KiB line, and a
/// log whose whole purpose is to be read should not be filled by something that is not.
pub fn sanitize_output_line(line: &str) -> Option<String> {
    const MAX: usize = 4096;
    let text = match line.find('\0') {
        Some(index) => &line[..index],
        None => line,
    };
    // Other control characters are not output either, but tab is (make and cargo indent with
    // it). This keeps the line readable instead of turning it into a row of escapes.
    let cleaned: String = text
        .chars()
        .filter(|c| *c == '\t' || !c.is_control())
        .collect();
    let trimmed = cleaned.trim_end();
    if trimmed.trim().is_empty() {
        return None;
    }
    if trimmed.len() > MAX {
        let mut cut = String::with_capacity(MAX + 16);
        cut.push_str(&trimmed[..MAX]);
        cut.push_str(" …[truncated]");
        return Some(cut);
    }
    Some(trimmed.to_string())
}

/// Whether a build failure is the daemon going away rather than the build being wrong.
///
/// Docker Desktop restarting mid-build, or its VM dying, surfaces as an RPC error from the
/// client: the build never got as far as reporting anything about the image. That is worth
/// distinguishing because the two need opposite responses -- one is retried, the other is
/// read -- and because the cache survives it, so the retry is usually cheap.
pub fn is_daemon_interruption(message: &str) -> bool {
    let lower = message.to_ascii_lowercase();
    const SIGNS: [&str; 9] = [
        "failed to receive status",
        "rpc error",
        "error reading from server",
        "cannot connect to the docker daemon",
        "error during connect",
        "is the docker daemon running",
        "unexpected eof",
        "connection reset by peer",
        "connection refused",
    ];
    SIGNS.iter().any(|sign| lower.contains(sign))
}

pub fn parse_versions(json: &str) -> (String, Option<String>) {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(json) else {
        return (String::new(), None);
    };
    let text = |at: Option<&serde_json::Value>| {
        at.and_then(|value| value.as_str())
            .unwrap_or_default()
            .trim()
            .to_string()
    };
    let client = text(value.get("Client").and_then(|client| client.get("Version")));
    let server = value
        .get("Server")
        .and_then(|server| server.get("Version"))
        .and_then(|version| version.as_str())
        .map(|version| version.trim().to_string())
        .filter(|version| !version.is_empty());
    (client, server)
}

/// The operating system and daemon name out of `docker info --format '{{json .}}'`.
pub fn parse_info(json: &str) -> (String, String) {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(json) else {
        return (String::new(), String::new());
    };
    let text = |key: &str| {
        value
            .get(key)
            .and_then(|field| field.as_str())
            .unwrap_or_default()
            .trim()
            .to_string()
    };
    (text("OperatingSystem"), text("Name"))
}

/// How long a build may produce no output at all before it is stopped.
///
/// Generous on purpose: this is not a timeout on the work, it is a limit on silence, and every
/// step that can take minutes -- apt, npm, cargo -- prints as it goes. A build that has said
/// nothing for ten minutes is not one anybody is waiting for. On this machine it was an `npm
/// install -g` behind a connection that had stopped answering, and the operator's only way out
/// was to close the app and kill the `docker build` it had left behind.
pub const BUILD_SILENCE_LIMIT: std::time::Duration = std::time::Duration::from_secs(600);

/// The builds running in this process, so one can be stopped from outside.
///
/// Keyed by image tag, because that is what everything else names a build by: the Activity tab's
/// progress, the Run that is waiting on it, and the button that wants it to stop. The flag is
/// how a cancelled build knows to say it was cancelled rather than looking like one that broke
/// on its own.
type LiveBuild = (
    String,
    u32,
    std::sync::Arc<std::sync::atomic::AtomicBool>,
);

static LIVE_BUILDS: std::sync::Mutex<Vec<LiveBuild>> = std::sync::Mutex::new(Vec::new());

fn register_build(tag: &str, pid: u32, cancelled: &std::sync::Arc<std::sync::atomic::AtomicBool>) {
    let mut builds = LIVE_BUILDS.lock().unwrap_or_else(|p| p.into_inner());
    builds.retain(|(name, _, _)| name != tag);
    builds.push((tag.to_string(), pid, std::sync::Arc::clone(cancelled)));
}

fn unregister_build(tag: &str) {
    let mut builds = LIVE_BUILDS.lock().unwrap_or_else(|p| p.into_inner());
    builds.retain(|(name, _, _)| name != tag);
}

/// Stop the build of `tag`, if one is running. Returns whether there was one.
///
/// The kill is the `docker` client and its children: BuildKit does its own work in the daemon,
/// but it stops when the client that asked for it goes away, and the client is what the app
/// started and can reach.
pub fn cancel_build(tag: &str) -> bool {
    let found = {
        let builds = LIVE_BUILDS.lock().unwrap_or_else(|p| p.into_inner());
        builds
            .iter()
            .find(|(name, _, _)| name == tag)
            .map(|(_, pid, cancelled)| {
                cancelled.store(true, std::sync::atomic::Ordering::SeqCst);
                *pid
            })
    };
    match found {
        Some(pid) => {
            tracing::warn!(pid, tag, "a build was cancelled");
            kill_process_tree(pid);
            true
        }
        None => false,
    }
}

/// Whether anything is being built right now.
pub fn builds_in_flight() -> Vec<String> {
    LIVE_BUILDS
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .iter()
        .map(|(tag, _, _)| tag.clone())
        .collect()
}

/// Whether a build that has been silent this long should be stopped.
///
/// Split out from the watchdog that applies it so the rule can be read, and tested, without
/// running a build at all.
/// The first words of the message a build returns when it was stopped on purpose: by the
/// operator's Stop button, or by the silence watchdog.
///
/// Both are recognised so that neither is mistaken for a daemon that went away. A cancelled
/// build's output usually ends with BuildKit's `failed to receive status`, which is one of the
/// signs `is_daemon_interruption` looks for -- so cancelling a build used to be read as the
/// daemon going away, and the build was *retried* after a wait of up to three minutes. That is
/// what an operator saw as the Run button stuck on "Starting…" after asking for it to stop.
pub const STOPPED_BY_OPERATOR: &str = "the build was stopped.";
pub const STOPPED_FOR_SILENCE: &str = "the build produced no output for";

/// Whether this failure was a stop somebody asked for, rather than something going wrong.
///
/// Deliberately separate from `is_daemon_interruption`: the two look alike in the output and
/// mean opposite things about what to do next.
pub fn is_our_own_stop(message: &str) -> bool {
    message.contains(STOPPED_BY_OPERATOR) || message.contains(STOPPED_FOR_SILENCE)
}

pub fn build_has_gone_quiet(quiet_for: std::time::Duration) -> bool {
    quiet_for >= BUILD_SILENCE_LIMIT
}

/// Stop a process, and anything it started.
///
/// `Child::kill` cannot reach a `docker` client's own children, and a build that has stopped
/// answering usually has one: the helper behind it is what is actually stuck.
pub fn kill_process_tree(pid: u32) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        let mut command = std::process::Command::new("taskkill");
        command.args(["/PID", &pid.to_string(), "/T", "/F"]);
        command.creation_flags(CREATE_NO_WINDOW);
        return command.status().map(|status| status.success()).unwrap_or(false);
    }
    #[cfg(not(windows))]
    {
        // `kill` is in POSIX, so this needs no dependency; the group first, so a client's own
        // children go with it.
        return std::process::Command::new("kill")
            .args(["-9", &format!("-{pid}")])
            .status()
            .or_else(|_| {
                std::process::Command::new("kill")
                    .args(["-9", &pid.to_string()])
                    .status()
            })
            .map(|status| status.success())
            .unwrap_or(false);
    }
}

/// Stop any `docker` client this process started that is still running.
///
/// Windows does not end a child when its parent exits, so a build that has stopped answering
/// outlives the app that started it -- one was found still running an hour and a half later,
/// holding the image tag it was building, which is what the *next* build then waits for. The
/// app's shutdown is polite first and bounded second; this is what happens to whatever is left
/// when the budget runs out.
///
/// Children are found by asking the operating system for this process's own children rather than
/// by keeping a list of every spawn: a list is one more thing to forget to update, and the hung
/// `docker run` probes that were also left behind came from a call site that would have been
/// easy to miss.
pub fn terminate_our_clients() -> Vec<u32> {
    let me = std::process::id();
    let mut killed = Vec::new();
    for (pid, name) in own_children(me) {
        // Only what this app starts. Anything else a user has running is theirs.
        if !name.to_lowercase().contains("docker") {
            continue;
        }
        if kill_process_tree(pid) {
            killed.push(pid);
        }
    }
    killed
}

/// This process's children, as `(pid, executable name)`.
fn own_children(me: u32) -> Vec<(u32, String)> {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        // `tasklist` cannot filter by parent, so this asks in PowerShell. It runs once, on the
        // way out, which is the only place a few hundred milliseconds do not matter.
        let script = format!(
            "Get-CimInstance Win32_Process -Filter \"ParentProcessId={me}\" | ForEach-Object {{ \
             \"$($_.ProcessId) $($_.Name)\" }}"
        );
        let mut command = std::process::Command::new("powershell");
        command.args(["-NoProfile", "-NonInteractive", "-Command", &script]);
        command.creation_flags(CREATE_NO_WINDOW);
        let Ok(output) = command.output() else {
            return Vec::new();
        };
        return String::from_utf8_lossy(&output.stdout)
            .lines()
            .filter_map(|line| {
                let mut parts = line.split_whitespace();
                let pid = parts.next()?.parse().ok()?;
                let name = parts.next()?.to_string();
                Some((pid, name))
            })
            .collect();
    }
    #[cfg(not(windows))]
    {
        let Ok(output) = std::process::Command::new("pgrep")
            .args(["-P", &me.to_string()])
            .output()
        else {
            return Vec::new();
        };
        return String::from_utf8_lossy(&output.stdout)
            .lines()
            .filter_map(|line| line.trim().parse::<u32>().ok())
            .map(|pid| (pid, "docker".to_string()))
            .collect();
    }
}

pub const BUILD_TAIL_LINES: usize = 8;

/// The message a failed build reports, including the end of its own output.
///
/// Split out from `build` so it can be tested without Docker, and so the shape of a
/// failure is a decision in one place rather than string-formatting at a call site.
pub fn describe_build_failure(tail: &[String]) -> String {
    // Empty lines are dropped: buildkit separates steps with them, and the line that
    // explains a failure is never blank.
    let useful: Vec<&str> = tail
        .iter()
        .map(|line| line.trim())
        .filter(|line| !line.is_empty())
        .collect();
    if useful.is_empty() {
        return "the build failed and reported no output. Run `docker build` against the runtime directory by hand."
            .to_string();
    }
    let start = useful.len().saturating_sub(BUILD_TAIL_LINES);
    format!(
        "the build failed. Last {} line(s) of its output:\n{}",
        useful.len() - start,
        useful[start..].join("\n")
    )
}

pub fn parse_build_step(line: &str) -> Option<(u32, u32)> {
    // BuildKit: the first `[n/m]` on the line.
    if let Some(open) = line.find('[') {
        if let Some(close) = line[open..].find(']') {
            if let Some(step) = parse_pair(&line[open + 1..open + close]) {
                return Some(step);
            }
        }
    }
    // Classic builder: `Step n/m`.
    if let Some(at) = line.find("Step ") {
        let rest = &line[at + 5..];
        let end = rest.find(|c: char| !c.is_ascii_digit() && c != '/').unwrap_or(rest.len());
        if let Some(step) = parse_pair(&rest[..end]) {
            return Some(step);
        }
    }
    None
}

/// `n/m` with n <= m and m > 0.
fn parse_pair(value: &str) -> Option<(u32, u32)> {
    let (left, right) = value.trim().split_once('/')?;
    let step: u32 = left.trim().parse().ok()?;
    let total: u32 = right.trim().parse().ok()?;
    // A total of zero would divide by zero downstream; a step past the total is not
    // progress and would push a bar past 100%.
    if total == 0 || step > total {
        return None;
    }
    Some((step, total))
}

/// Minimal `which`: avoids a dependency for something this small.
fn which(program: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    let exts: Vec<String> = if cfg!(windows) {
        std::env::var("PATHEXT")
            .unwrap_or_else(|_| ".COM;.EXE;.BAT;.CMD".to_string())
            .split(';')
            .map(|s| s.to_lowercase())
            .collect()
    } else {
        vec![String::new()]
    };
    for dir in std::env::split_paths(&path) {
        for ext in &exts {
            let candidate = if ext.is_empty() {
                dir.join(program)
            } else {
                dir.join(format!("{program}{ext}"))
            };
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
}

    /* --- build progress ---------------------------------------------------- */

    /// The exact lines this was written against, captured from a real build, including
    /// the "internal" lines that must not be mistaken for progress.
    #[test]
    fn the_shapes_a_real_build_actually_prints_are_handled() {
        assert_eq!(parse_build_step("#5 [2/2] RUN echo probe-alpha"), Some((2, 2)));
        assert_eq!(parse_build_step("#1 [internal] load build definition from Dockerfile"), None);
        assert_eq!(parse_build_step("#1 DONE 0.2s"), None);
        assert_eq!(parse_build_step("#5 0.299 probe-alpha"), None);
    }

    #[test]
    fn buildkit_step_lines_are_read() {
        assert_eq!(
            parse_build_step("#7 [4/23] RUN set -eux; apt-get install jq"),
            Some((4, 23))
        );
        assert_eq!(parse_build_step("#12 [12/23] COPY skills/ /home/"), Some((12, 23)));
    }

    #[test]
    fn classic_builder_step_lines_are_read() {
        assert_eq!(parse_build_step("Step 4/23 : RUN apt-get install jq"), Some((4, 23)));
        assert_eq!(parse_build_step(" ---> Running in abc"), None);
    }

    /// A line with no step must not produce a number, or the bar would jump about for
    /// reasons the operator cannot see.
    #[test]
    fn a_line_without_a_step_reports_nothing() {
        for line in ["", " ---> abc123", "Successfully built abc", "#5 exporting layers"] {
            assert_eq!(parse_build_step(line), None, "{line:?}");
        }
    }

    #[test]
    fn impossible_steps_are_rejected_rather_than_shown() {
        assert_eq!(parse_build_step("#1 [0/0] FROM node"), None);
        assert_eq!(parse_build_step("#1 [9/4] FROM node"), None);
        assert_eq!(parse_build_step("#1 [a/b] FROM node"), None);
    }

/// The probe reads JSON that Docker produces, and the two pieces it needs from it. Worth
/// testing on its own: the shapes below are trimmed copies of real output, including the
/// daemon-less case, which is the one that has to be distinguished from a parse failure.
/// The words for a daemon that is not answering, which have to separate two situations an
/// operator can see differently on their own screen.
#[cfg(test)]
mod unreachable_tests {
    use super::*;

    #[test]
    fn a_running_desktop_is_not_told_to_start_itself() {
        let running = unreachable_detail(true);
        assert!(running.contains("Docker Desktop is running"));
        assert!(running.contains("daemon"), "name the part that is not answering");
        assert!(
            !running.contains("Start it"),
            "it cannot be told to start what is already running: {running}"
        );
    }

    #[test]
    fn a_desktop_that_is_not_running_is_told_to_start() {
        let stopped = unreachable_detail(false);
        assert!(stopped.contains("Docker Desktop is not running"));
        assert!(stopped.contains("Start it"));
    }

    #[test]
    fn the_two_messages_are_different() {
        assert_ne!(unreachable_detail(true), unreachable_detail(false));
    }
}

/// The output filter, tested on the case it exists for: the 32 KiB of NULs a dying daemon
/// leaves in the pipe, which was written into the build log as if it were a line.
#[cfg(test)]
mod build_output_tests {
    use super::*;

    #[test]
    fn a_normal_line_is_kept() {
        assert_eq!(
            sanitize_output_line("#5 [2/3] RUN apt-get update"),
            Some("#5 [2/3] RUN apt-get update".to_string())
        );
        assert_eq!(
            sanitize_output_line("\tcompiling htmlq v0.1.0"),
            Some("\tcompiling htmlq v0.1.0".to_string()),
            "cargo and make indent with tabs"
        );
    }

    #[test]
    fn a_zero_filled_chunk_from_a_dying_daemon_is_not_content() {
        let junk = "\0".repeat(32_000);
        assert_eq!(sanitize_output_line(&junk), None);
        assert_eq!(sanitize_output_line(""), None);
        assert_eq!(sanitize_output_line("   \r"), None);
    }

    #[test]
    fn text_before_the_nulls_is_kept_and_nothing_after_it_is() {
        let line = format!("ERROR: failed to build{}", "\0".repeat(32_000));
        assert_eq!(
            sanitize_output_line(&line),
            Some("ERROR: failed to build".to_string())
        );
    }

    #[test]
    fn an_absurdly_long_line_is_cut_rather_than_written_whole() {
        let line = "x".repeat(20_000);
        let kept = sanitize_output_line(&line).expect("text is text");
        assert!(kept.len() < 4200, "{}", kept.len());
        assert!(kept.ends_with("[truncated]"));
    }

    /// The failure this comes from, verbatim.
    #[test]
    fn the_daemon_going_away_is_recognised_as_an_interruption() {
        assert!(is_daemon_interruption(
            "failed to build: failed to receive status: rpc error: code = Unavailable desc = error reading from server: EOF"
        ));
        assert!(is_daemon_interruption(
            "Cannot connect to the Docker daemon at unix:///var/run/docker.sock. Is the docker daemon running?"
        ));
    }

    /// And a build that is genuinely wrong is not, because the two get opposite responses.
    #[test]
    fn a_real_build_failure_is_not_an_interruption() {
        assert!(!is_daemon_interruption(
            "the command '/bin/sh -c apt-get install -y curl,git' returned a non-zero code: 100"
        ));
        assert!(!is_daemon_interruption("E: Unable to locate package curl,git"));
    }
}

#[cfg(test)]
mod probe_parsing_tests {
    use super::*;

    const WITH_SERVER: &str = r#"{"Client":{"Version":"29.8.2","Os":"windows"},
        "Server":{"Version":"29.8.2","Os":"linux"}}"#;

    /// With no daemon the client block is still printed and the server one is null.
    const WITHOUT_SERVER: &str = r#"{"Client":{"Version":"29.8.2"},"Server":null}"#;

    #[test]
    fn the_versions_come_out_of_one_call() {
        assert_eq!(
            parse_versions(WITH_SERVER),
            ("29.8.2".to_string(), Some("29.8.2".to_string()))
        );
    }

    #[test]
    fn a_daemon_that_is_not_running_is_a_missing_server_not_an_error() {
        let (client, server) = parse_versions(WITHOUT_SERVER);
        assert_eq!(client, "29.8.2", "the client version is still known");
        assert_eq!(server, None, "and the server one is what tells the caller to refuse");
    }

    /// Anything that is not the expected JSON is "unknown", never a panic and never a
    /// half-filled version string.
    #[test]
    fn nonsense_is_reported_as_unknown() {
        assert_eq!(parse_versions(""), (String::new(), None));
        assert_eq!(parse_versions("error during connect"), (String::new(), None));
        assert_eq!(parse_versions("{}"), (String::new(), None));
        assert_eq!(parse_info("not json"), (String::new(), String::new()));
    }

    #[test]
    fn the_operating_system_and_name_come_out_of_one_call() {
        let info = r#"{"OperatingSystem":"Docker Desktop","Name":"docker-desktop","NCPU":8}"#;
        assert_eq!(parse_info(info), ("Docker Desktop".to_string(), "docker-desktop".to_string()));
    }
}

/// The build watchdog's rule. It is the one part of that machinery which is a decision rather
/// than a side effect, so it is the part that can be asserted: silence, not elapsed time, is the
/// signal, and the limit is generous because every slow step prints as it goes.
#[cfg(test)]
mod build_watchdog_tests {
    use super::*;
    use std::time::Duration;

    /// A stop we asked for is not a daemon that went away, and the difference decides whether a
    /// build is retried behind the operator's back. The messages are the real ones, and the
    /// daemon one is from a real failure on this machine.
    #[test]
    fn a_build_we_stopped_is_never_mistaken_for_a_daemon_that_went_away() {
        assert!(is_our_own_stop(
            "the build was stopped. Nothing is wrong with the image files"
        ));
        assert!(is_our_own_stop(
            "the build produced no output for 10 minutes, so it was stopped"
        ));
        assert!(
            !is_our_own_stop("failed to receive status: rpc error: code = Unavailable"),
            "a daemon that went away is not a stop we asked for"
        );
        assert!(
            !is_our_own_stop("E: Unable to locate package curl,git,jq"),
            "and neither is a build that failed on its own"
        );
    }

    #[test]
    fn a_build_is_only_stopped_after_it_has_been_quiet_for_the_limit() {
        assert!(!build_has_gone_quiet(Duration::from_secs(0)));
        assert!(!build_has_gone_quiet(Duration::from_secs(9 * 60)));
        assert!(build_has_gone_quiet(BUILD_SILENCE_LIMIT));
        assert!(build_has_gone_quiet(Duration::from_secs(11 * 60)));
        // Long enough that a slow `cargo install` or a cold apt mirror is not mistaken for a
        // hang, which is the failure mode of a watchdog set too tight.
        assert!(BUILD_SILENCE_LIMIT >= Duration::from_secs(5 * 60));
    }

    /// A cancel has to actually stop something. This spawns a real process, registers it the way
    /// a build registers itself, and checks that cancelling ends it and marks it -- the
    /// alternative is a button that reports success while the build carries on.
    #[test]
    fn cancelling_a_build_stops_the_process_it_was_told_about() {
        let tag = format!("deepsand/runtime:cancel-test-{}", crate::now_ms());
        #[cfg(windows)]
        let spawned = std::process::Command::new("cmd")
            .args(["/C", "ping -n 30 127.0.0.1 > NUL"])
            .spawn();
        #[cfg(not(windows))]
        let spawned = std::process::Command::new("sleep").arg("30").spawn();
        let mut child = spawned.expect("a process to cancel");

        let cancelled = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        register_build(&tag, child.id(), &cancelled);
        assert!(builds_in_flight().contains(&tag), "a build is in flight");

        assert!(cancel_build(&tag), "the registered build is found");
        assert!(
            cancelled.load(std::sync::atomic::Ordering::SeqCst),
            "and is marked cancelled, so its failure can say so"
        );

        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        let mut exited = false;
        while std::time::Instant::now() < deadline {
            if matches!(child.try_wait(), Ok(Some(_))) {
                exited = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        assert!(exited, "the process was stopped");
        let _ = child.kill();

        unregister_build(&tag);
        assert!(!cancel_build(&tag), "nothing to cancel is not a failure");
        assert!(!builds_in_flight().contains(&tag));
    }
}

#[cfg(test)]
mod build_failure_tests {
    use super::*;

    fn lines(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| value.to_string()).collect()
    }

    /// The message has to carry the end of the build's own output. The reason this exists
    /// is that a failure saying only "see the build log above" is undiagnosable once the
    /// window is closed.
    #[test]
    fn a_failed_build_reports_its_own_last_lines() {
        let message = describe_build_failure(&lines(&[
            "#16 3.082 E: Unable to locate package curl,git,jq",
            "#16 ERROR: process did not complete successfully",
        ]));
        assert!(message.contains("E: Unable to locate package"), "{message}");
        assert!(message.contains("did not complete successfully"), "{message}");
    }

    /// Only the tail, and never more than the cap: a toast is not a log viewer.
    #[test]
    fn a_chatty_build_is_truncated_to_the_last_lines() {
        let mut noisy: Vec<String> = (0..100).map(|i| format!("line {i}")).collect();
        noisy.push("the one that matters".to_string());
        let message = describe_build_failure(&noisy);

        assert!(message.contains("the one that matters"), "{message}");
        assert!(!message.contains("line 0\n"), "the start must be dropped: {message}");
        assert!(
            message.lines().count() <= BUILD_TAIL_LINES + 1,
            "at most {BUILD_TAIL_LINES} lines plus the sentence: {message}"
        );
    }

    /// Buildkit separates steps with blank lines; they are not the explanation.
    #[test]
    fn blank_separator_lines_are_not_what_gets_reported() {
        let message = describe_build_failure(&lines(&["#16 failing", "", "   ", ""]));
        assert_eq!(message.lines().count(), 2, "{message}");
    }

    /// A build that died before printing anything still has to say something useful.
    #[test]
    fn a_silent_failure_says_how_to_see_more() {
        let message = describe_build_failure(&[]);
        assert!(message.contains("docker build"), "{message}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn which_finds_a_program_that_must_exist() {
        let cargo = which(if cfg!(windows) { "cmd" } else { "sh" });
        assert!(cargo.is_some(), "expected to locate a shell on PATH");
    }

    #[test]
    fn which_returns_none_for_nonsense() {
        assert!(which("deepsand-definitely-not-installed-xyz").is_none());
    }

    #[test]
    fn probing_reports_unavailable_instead_of_panicking_when_the_binary_is_missing() {
        let docker = Docker::with_program(if cfg!(windows) { "deepsand-no-docker.exe" } else { "deepsand-no-docker" });
        let status = docker.probe("deepsand/runtime:none");
        assert!(!status.available);
        assert!(!status.detail.is_empty());
    }
}

/// Run a command, ending it if it outstays `limit`.
///
/// The watcher is a thread rather than a poll loop in the caller because `wait_with_output` is the
/// only way to collect both pipes without deadlocking on a full one: the kill comes from outside
/// and that call returns by itself. `killed` is what lets the caller tell "this process was stopped
/// by the limit" from "this process said something and failed", which are the same shape otherwise
/// and mean very different things.
/// What to do about an image the sandbox is about to need.
///
/// Kept pure so the decisions can be tested without docker: each of the three answers is a
/// different bug if it is wrong. "Ready" too early runs a tag that is not there, and docker
/// reports that as "pull access denied", which reads like a permissions problem. "Wait" too
/// eagerly hangs a launch that nothing is building. "Give up" too late is the hang.
#[derive(Debug, PartialEq, Eq)]
pub enum ImageWait {
    Ready,
    Wait,
    GiveUp(String),
}

/// `grace_checks_left` is how many more checks to allow for a build that has been asked for
/// but has not registered itself yet: the request and the registration are not one act, and
/// giving up in that gap would refuse a launch that was about to be fine.
pub fn image_wait_step(present: bool, building: bool, grace_checks_left: u32, image: &str) -> ImageWait {
    if present {
        return ImageWait::Ready;
    }
    if building {
        return ImageWait::Wait;
    }
    if grace_checks_left > 0 {
        return ImageWait::Wait;
    }
    ImageWait::GiveUp(format!(
        "{image} is not built and nothing is building it. Build it from the project's Activity tab, then start again."
    ))
}

#[cfg(test)]
mod image_wait_tests {
    use super::*;

    #[test]
    fn an_image_that_is_there_is_ready_whatever_else_is_happening() {
        assert_eq!(image_wait_step(true, true, 0, "img"), ImageWait::Ready);
        assert_eq!(image_wait_step(true, false, 0, "img"), ImageWait::Ready);
    }

    #[test]
    fn an_image_being_built_is_waited_for() {
        assert_eq!(image_wait_step(false, true, 0, "img"), ImageWait::Wait);
    }

    /// A build that was just asked for has not registered yet; refusing in that gap would
    /// break the launch it was meant to protect.
    #[test]
    fn a_build_that_has_not_registered_yet_is_given_a_moment() {
        assert_eq!(image_wait_step(false, false, 5, "img"), ImageWait::Wait);
    }

    #[test]
    fn an_image_nothing_is_building_is_reported_rather_than_waited_for() {
        match image_wait_step(false, false, 0, "img") {
            ImageWait::GiveUp(message) => assert!(message.contains("img")),
            other => panic!("expected a refusal, got {other:?}"),
        }
    }
}

fn wait_bounded(
    mut cmd: Command,
    limit: std::time::Duration,
) -> std::result::Result<std::process::Output, String> {
    cmd.stdin(Stdio::null());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());
    let mut child = cmd
        .spawn()
        .map_err(|err| format!("could not start it: {err}"))?;
    let stdout = child.stdout.take().expect("the stdout pipe was requested");
    let stderr = child.stderr.take().expect("the stderr pipe was requested");

    // The pipes are drained on threads so a chatty child can never fill one and block while
    // we poll for its exit. The deadline is enforced with the child's own process handle:
    // `kill()` is TerminateProcess on Windows, which cannot be refused the way a taskkill of
    // the tree can be -- and a previous version of this bound waited forever because its
    // taskkill had been refused.
    let stdout_thread = std::thread::spawn(move || drain(stdout));
    let stderr_thread = std::thread::spawn(move || drain(stderr));

    let deadline = std::time::Instant::now() + limit;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if std::time::Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                // Joined so the pipes are closed before the error is returned, but the
                // output of a command that had to be killed is not worth reporting.
                let _ = stdout_thread.join();
                let _ = stderr_thread.join();
                return Err(format!(
                    "it gave no answer within {}s, so it was killed. This command is not the problem: \
                     something inside Docker is not answering, and restarting Docker Desktop is the usual \
                     fix.",
                    limit.as_secs()
                ));
            }
            Ok(None) => std::thread::sleep(std::time::Duration::from_millis(50)),
            Err(err) => {
                let _ = child.kill();
                return Err(format!("could not be waited on: {err}"));
            }
        }
    };
    let stdout = stdout_thread.join().unwrap_or_default();
    let stderr = stderr_thread.join().unwrap_or_default();
    Ok(std::process::Output {
        status,
        stdout,
        stderr,
    })
}

/// Read a child pipe to the end on a helper thread.
fn drain(mut pipe: impl std::io::Read) -> Vec<u8> {
    let mut bytes = Vec::new();
    let _ = pipe.read_to_end(&mut bytes);
    bytes
}

#[cfg(test)]
mod command_timeout_tests {
    use super::*;

    /// A command that ignores its limit hangs the caller forever, which is the shape of the bug
    /// this bound exists for. The child sleeps far longer than the limit, and the limit is short,
    /// so the test is short too.
    #[test]
    fn a_command_that_outstays_its_limit_is_ended_and_reported() {
        let mut cmd = if cfg!(windows) {
            let mut cmd = Command::new("ping");
            cmd.args(["-n", "20", "127.0.0.1"]);
            cmd
        } else {
            let mut cmd = Command::new("sleep");
            cmd.arg("20");
            cmd
        };
        cmd.stdout(Stdio::null());
        let started = std::time::Instant::now();
        let outcome = wait_bounded(cmd, std::time::Duration::from_millis(400));
        let elapsed = started.elapsed();
        let message = outcome.expect_err("the limit has to end it, not the command");
        assert!(message.contains("gave no answer within"), "and say why: {message}");
        assert!(
            elapsed < std::time::Duration::from_secs(10),
            "promptly, not eventually: {elapsed:?}"
        );
    }

    /// The ordinary case is untouched: a command that finishes is a command that finishes.
    #[test]
    fn a_command_that_finishes_returns_its_output() {
        let mut cmd = if cfg!(windows) {
            let mut cmd = Command::new("cmd");
            cmd.args(["/c", "echo", "hello"]);
            cmd
        } else {
            let mut cmd = Command::new("echo");
            cmd.arg("hello");
            cmd
        };
        cmd.stdout(Stdio::piped());
        let output = wait_bounded(cmd, std::time::Duration::from_secs(30)).expect("should run");
        assert!(String::from_utf8_lossy(&output.stdout).contains("hello"));
    }
}
