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

    fn run_raw(&self, args: &[OsString]) -> Result<std::process::Output> {
        let mut cmd = self.command();
        cmd.args(args);
        cmd.output().map_err(|err| {
            SandboxError::DockerUnavailable(format!(
                "could not run {}: {err}. Is Docker Desktop running?",
                self.program.display()
            ))
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

    fn fmt(&self, args: &[&str]) -> Vec<String> {
        args.iter().map(|s| (*s).to_string()).collect()
    }

    /// Probe the installation: versions, whether it is Docker Desktop, and
    /// whether the runtime image is present.
    pub fn probe(&self, image: &str) -> DockerStatus {
        let mut status = DockerStatus::default();

        status.client_version = self
            .try_run(&self.fmt(&["version", "--format", "{{.Client.Version}}"]))
            .unwrap_or_default();

        match self.try_run(&self.fmt(&["version", "--format", "{{.Server.Version}}"])) {
            Some(version) if !version.is_empty() && !version.contains("error") => {
                status.available = true;
                status.server_version = version;
            }
            _ => {
                status.detail = "the Docker daemon is not reachable. Start Docker Desktop and try again.".to_string();
                return status;
            }
        }

        status.operating_system = self
            .try_run(&self.fmt(&["info", "--format", "{{.OperatingSystem}}"]))
            .unwrap_or_default();
        let name = self.try_run(&self.fmt(&["info", "--format", "{{.Name}}"])).unwrap_or_default();
        status.desktop = status.operating_system.contains("Docker Desktop") || name.contains("docker-desktop");
        status.image_present = self.image_present(image);
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
        let args = self.fmt(&[
            "run",
            "--rm",
            "--network=none",
            "--entrypoint=/bin/cat",
            image,
            path,
        ]);
        self.run(&args).map_err(|err| match err {
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
    pub fn build(
        &self,
        context: &Path,
        tag: &str,
        build_args: &[(&str, String)],
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

        // Drain stdout on its own thread so a chatty build cannot deadlock
        // against the stderr reader.
        let stdout = child.stdout.take().map(BufReader::new);
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
        let mut sink = |line: &str| {
            keep_tail(line, &mut tail);
            sink(line);
        };

        if let Some(reader) = child.stderr.take().map(BufReader::new) {
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

        let status = child.wait()?;
        if !status.success() {
            return Err(SandboxError::Docker {
                command: format!("docker build -t {tag} {}", context.display()),
                stderr: describe_build_failure(&tail),
            });
        }
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

        self.try_run(&args).is_some_and(|out| out.contains("sessions-index.json"))
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

        let result = self.try_run(&args);
        let _ = std::fs::remove_file(&probe);

        match result {
            Some(out) if out.contains(&token) => SharingCheck::ok(),
            _ => SharingCheck::unavailable(format!(
                "Docker cannot read files from {} inside a container.\n\n\
                 Docker Desktop only shares the directories listed under\n\
                 Settings -> Resources -> File Sharing. This machine currently lists none, so a bind\n\
                 mount silently produces empty directories instead of a readable tree. Add the drive that\n\
                 holds your projects (for example C:\\) there, choose Apply & Restart, then try again.\n\n\
                 On Linux, check that the path is not under a mount your Docker daemon cannot see.",
                dir.display()
            )),
        }
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
