//! Importing a repository with the host's own git.
//!
//! The clone runs on the host, not in the sandbox: the project has to exist before it can be
//! mounted, and a sandbox is the thing a project is a precondition for. The machine's own git
//! configuration is used first -- its credential helper, its SSH agent, its keys -- and only a
//! refusal that a typed credential could answer is reported back as one, so the window knows
//! whether asking for a login is worth it.
//!
//! Nothing here writes a host path of its own: the caller decides where the clone goes, and the
//! store's guards decide whether that place may become a project.

use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::error::{Result, SandboxError};

/// How long one clone may take before git is ended. A large repository takes real minutes; one
/// that outlives this is not working, and a GUI has no terminal to interrupt it from.
pub const CLONE_TIMEOUT: Duration = Duration::from_secs(30 * 60);

/// The `-c` value that answers git's credential request from the environment.
///
/// A token in an argument vector is readable by any local user with `ps`, and a token in a
/// temporary file is readable by anything that can read the file, so neither is used: the two
/// values are read from the environment of the one process that needs them. Git for Windows runs
/// a `!`-prefixed helper through the `sh` it ships, so this works on every platform the app is
/// built for.
const CREDENTIAL_HELPER: &str =
    "credential.helper=!f() { echo username=\"$DEEPSAND_GIT_USER\"; echo password=\"$DEEPSAND_GIT_SECRET\"; }; f";

/// A credential the operator typed in: used for one clone, then dropped.
#[derive(Debug, Clone)]
pub struct GitCredential {
    pub username: String,
    pub secret: String,
}

/// What one clone attempt did.
#[derive(Debug, Clone)]
pub struct CloneOutcome {
    pub ok: bool,
    /// The repository asked for a login the machine itself could not give, and the URL is one a
    /// typed credential can help with.
    pub needs_credentials: bool,
    /// Git's own last words, sanitized: what to show when nothing was cloned.
    pub detail: String,
}

/// The host's git.
#[derive(Debug, Clone)]
pub struct Git {
    program: PathBuf,
}

impl Git {
    /// Find git: an explicit `DEEPSAND_GIT`, then the well-known install locations, then `PATH`.
    ///
    /// The same order `Docker::locate` uses, so "found" means the same thing for both.
    pub fn locate() -> Result<Self> {
        if let Ok(explicit) = std::env::var("DEEPSAND_GIT") {
            let path = PathBuf::from(explicit);
            if path.exists() {
                return Ok(Self { program: path });
            }
        }

        let candidates: &[&str] = if cfg!(windows) {
            &[
                r"C:\Program Files\Git\cmd\git.exe",
                r"C:\Program Files (x86)\Git\cmd\git.exe",
            ]
        } else {
            &["/usr/bin/git", "/usr/local/bin/git", "/opt/homebrew/bin/git"]
        };
        for candidate in candidates {
            let path = PathBuf::from(candidate);
            if path.exists() {
                return Ok(Self { program: path });
            }
        }
        if let Some(found) = crate::docker::which("git") {
            return Ok(Self { program: found });
        }

        Err(SandboxError::Other(anyhow::anyhow!(
            "git was not found on this machine. Install Git, then import again."
        )))
    }

    pub fn program(&self) -> &Path {
        &self.program
    }

    /// Clone `url` into `dest`, using the machine's own credentials unless one is given.
    ///
    /// The first attempt is exactly what a terminal would do -- git's configured credential
    /// helper, its SSH agent, its keys -- because that is the "default credentials on this
    /// machine" the operator already has. `needs_credentials` is set only when the refusal is one
    /// a typed credential could answer.
    pub fn clone(
        &self,
        url: &str,
        dest: &Path,
        credential: Option<&GitCredential>,
    ) -> Result<CloneOutcome> {
        validate_clone_url(url)?;

        let mut cmd = crate::docker::bare_command(&self.program);
        cmd.args(clone_args(url, dest, credential.is_some()));
        // A GUI has no terminal to answer a prompt, so git must never wait for one.
        cmd.env("GIT_TERMINAL_PROMPT", "0");
        if let Some(credential) = credential {
            cmd.env("DEEPSAND_GIT_USER", &credential.username);
            cmd.env("DEEPSAND_GIT_SECRET", &credential.secret);
        }

        match crate::docker::wait_bounded(cmd, CLONE_TIMEOUT) {
            Ok(output) if output.status.success() => Ok(CloneOutcome {
                ok: true,
                needs_credentials: false,
                detail: String::new(),
            }),
            Ok(output) => {
                let stderr = String::from_utf8_lossy(&output.stderr);
                Ok(CloneOutcome {
                    ok: false,
                    needs_credentials: looks_like_auth_failure(&stderr) && credential_can_help(url),
                    detail: git_detail(&stderr),
                })
            }
            // Ended on its deadline: not an authentication answer, and not a repository fault
            // either, so it is reported as what it is.
            Err(err) => Ok(CloneOutcome {
                ok: false,
                needs_credentials: false,
                detail: err,
            }),
        }
    }
}

/// The argv for one clone.
///
/// `-c` options come before the subcommand and `--` before the positionals, so a URL that begins
/// with a dash can never be read as an option.
pub fn clone_args(url: &str, dest: &Path, with_credential: bool) -> Vec<String> {
    let mut args: Vec<String> = Vec::new();
    if with_credential {
        // Drop the machine's helper chain, then install ours: exactly one credential is tried,
        // and the one that was just refused is not offered again.
        args.push("-c".to_string());
        args.push("credential.helper=".to_string());
        args.push("-c".to_string());
        args.push(CREDENTIAL_HELPER.to_string());
    }
    args.push("clone".to_string());
    args.push("--progress".to_string());
    args.push("--".to_string());
    args.push(url.to_string());
    args.push(dest.display().to_string());
    args
}

/// The folder a repository clones into, derived from its URL.
///
/// `None` rather than a guess when the URL does not end in a usable name: the name becomes a
/// directory on the host, so it is checked with the same care a path is.
pub fn repo_name_from_url(url: &str) -> Option<String> {
    let trimmed = url.trim().trim_end_matches('/');
    let without_query = trimmed.split(['?', '#']).next().unwrap_or(trimmed);

    // A scheme URL with no path names a host, not a repository.
    for scheme in ["https://", "http://", "ssh://", "git://"] {
        if let Some(after) = strip_scheme(without_query, scheme) {
            let path = after.split_once('/').map(|(_, path)| path).unwrap_or("");
            if path.trim_matches('/').is_empty() {
                return None;
            }
        }
    }

    let last = without_query.rsplit(['/', ':']).next()?;
    let name = last.strip_suffix(".git").unwrap_or(last);
    if name.is_empty() || name == "." || name == ".." {
        return None;
    }
    // Anything the host filesystem or git would have to mangle is not a name worth guessing at.
    if name.chars().any(|c| {
        c.is_control() || matches!(c, '<' | '>' | ':' | '"' | '\\' | '/' | '|' | '?' | '*')
    }) {
        return None;
    }
    Some(name.to_string())
}

/// Check a repository URL before git is asked to use it.
///
/// Two refusals are not about tidiness. A remote-helper URL (`ext::…`, `foo::…`) names a program
/// for git to run, which is not input this app passes on. And a URL carrying `user:token@` would
/// be written into the clone's `origin` for good, so those credentials belong in the sign-in
/// fields, where they are used once and never saved.
pub fn validate_clone_url(url: &str) -> Result<()> {
    let url = url.trim();
    if url.is_empty() {
        return Err(invalid("enter a repository URL"));
    }
    if url.chars().any(char::is_whitespace) || url.contains('\0') {
        return Err(invalid("a repository URL cannot contain spaces or control characters"));
    }
    if url.starts_with('-') {
        return Err(invalid("a repository URL cannot start with '-'"));
    }
    if url.contains("::") && !url.contains("://") {
        return Err(invalid(
            "that is a git remote-helper URL, which names a program to run; Deepsand will not",
        ));
    }

    if let Some(after) = strip_scheme(url, "https://").or_else(|| strip_scheme(url, "http://")) {
        let authority = after.split(['/', '?', '#']).next().unwrap_or("");
        if authority.is_empty() {
            return Err(invalid("that URL has no host"));
        }
        if authority.contains('@') {
            return Err(invalid(
                "remove the username and token from the URL and use the sign-in fields, so they do \
                 not become the repository's saved remote",
            ));
        }
        return Ok(());
    }
    if strip_scheme(url, "ssh://").is_some() || strip_scheme(url, "git://").is_some() {
        return Ok(());
    }
    if is_scp_like(url) {
        return Ok(());
    }

    Err(invalid("use an https://, ssh://, git:// or git@host:path repository URL"))
}

/// Whether a credential the operator types could help: only the HTTP(S) transports carry one.
///
/// An SSH URL is refused by keys, not by a password, so asking for one would be theatre.
pub fn credential_can_help(url: &str) -> bool {
    strip_scheme(url, "https://").is_some() || strip_scheme(url, "http://").is_some()
}

/// Whether git's output is a refusal a credential could answer, rather than a missing repository
/// or an unreachable host.
///
/// A private repository on a hosted forge usually answers "not found" rather than "forbidden",
/// so that is treated as a possible login wall: asking for a credential costs one attempt, while
/// not asking sends the operator hunting for a typo in the URL.
pub fn looks_like_auth_failure(stderr: &str) -> bool {
    const MARKERS: &[&str] = &[
        "authentication failed",
        "authentication required",
        "could not read username",
        "could not read password",
        "terminal prompts disabled",
        "http basic: access denied",
        "invalid username or password",
        "invalid credentials",
        "401 unauthorized",
        "403 forbidden",
        "permission denied (publickey)",
        "repository not found",
        "access denied",
        "support for password authentication was removed",
    ];
    let text = stderr.to_ascii_lowercase();
    MARKERS.iter().any(|marker| text.contains(marker))
}

/// The last few lines git said, sanitized, for a human.
fn git_detail(stderr: &str) -> String {
    let lines: Vec<String> = stderr
        .lines()
        .filter_map(crate::docker::sanitize_output_line)
        .filter(|line| !line.trim().is_empty())
        .collect();
    let tail: Vec<&str> = lines.iter().rev().take(10).rev().map(String::as_str).collect();
    if tail.is_empty() {
        "git gave no reason".to_string()
    } else {
        tail.join("\n")
    }
}

/// The part of `url` after `scheme`, case-insensitively, or `None` when it does not start with it.
fn strip_scheme<'a>(url: &'a str, scheme: &str) -> Option<&'a str> {
    let prefix = url.get(..scheme.len())?;
    prefix.eq_ignore_ascii_case(scheme).then(|| &url[scheme.len()..])
}

/// `user@host:path`, the form git also accepts without a scheme.
fn is_scp_like(url: &str) -> bool {
    let Some((before_path, path)) = url.split_once(':') else {
        return false;
    };
    if path.is_empty() || before_path.contains('/') {
        return false;
    }
    let Some((user, host)) = before_path.split_once('@') else {
        return false;
    };
    !user.is_empty() && !host.is_empty()
}

fn invalid(message: &str) -> SandboxError {
    SandboxError::Other(anyhow::anyhow!(message.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_repository_name_comes_out_of_every_url_form() {
        for (url, expected) in [
            ("https://github.com/foo/bar.git", "bar"),
            ("https://github.com/foo/bar", "bar"),
            ("https://github.com/foo/bar/", "bar"),
            ("git@github.com:foo/bar.git", "bar"),
            ("ssh://git@github.com/foo/bar.git", "bar"),
            ("git://github.com/foo/bar.git", "bar"),
            ("https://host:8443/foo/bar.git?ref=main", "bar"),
        ] {
            assert_eq!(repo_name_from_url(url).as_deref(), Some(expected), "{url}");
        }
    }

    /// A host is not a repository, and a name that has to be mangled is not a name to guess at.
    #[test]
    fn a_url_that_names_no_repository_has_no_name() {
        for url in [
            "https://github.com",
            "https://github.com/",
            "",
            "https://github.com/foo/..",
            "https://github.com/foo/.",
        ] {
            assert_eq!(repo_name_from_url(url), None, "{url} should have no name");
        }
    }

    /// `ext::` names a program for git to run, which is exactly the input this must not accept.
    #[test]
    fn a_remote_helper_url_is_refused() {
        assert!(validate_clone_url("ext::sh -c 'echo pwned'").is_err());
        assert!(validate_clone_url("foo::bar").is_err());
    }

    /// Credentials in the URL would be written into the clone's `origin` and stayed there.
    #[test]
    fn credentials_in_a_url_are_refused_because_they_would_be_saved() {
        let err = validate_clone_url("https://user:token@github.com/foo/bar.git")
            .unwrap_err()
            .to_string();
        assert!(err.contains("sign-in"), "got {err}");
    }

    #[test]
    fn the_ordinary_url_forms_are_accepted() {
        for url in [
            "https://github.com/foo/bar.git",
            "http://git.internal/foo/bar",
            "ssh://git@github.com/foo/bar.git",
            "git://github.com/foo/bar.git",
            "git@github.com:foo/bar.git",
        ] {
            assert!(validate_clone_url(url).is_ok(), "{url} should be accepted");
        }
    }

    /// A URL is a positional, but git parses options first, so even a refused one must not be
    /// able to reach an option position.
    #[test]
    fn a_url_that_starts_with_a_dash_cannot_become_an_option() {
        assert!(validate_clone_url("--upload-pack=touch /tmp/x").is_err());
        let args = clone_args("https://github.com/foo/bar.git", Path::new("/tmp/bar"), false);
        let separator = args.iter().position(|arg| arg == "--").unwrap();
        let url = args.iter().position(|arg| arg.contains("github.com")).unwrap();
        assert!(separator < url, "the `--` must come before the URL: {args:?}");
    }

    #[test]
    fn an_auth_failure_is_told_from_an_unreachable_host() {
        assert!(looks_like_auth_failure("fatal: Authentication failed for 'https://x/foo/bar.git/'"));
        assert!(looks_like_auth_failure("remote: Repository not found."));
        assert!(looks_like_auth_failure(
            "fatal: could not read Username for 'https://x': terminal prompts disabled"
        ));
        assert!(!looks_like_auth_failure(
            "fatal: unable to access 'https://x/': Could not resolve host: x"
        ));
    }

    /// SSH is refused by keys rather than a password, so a typed credential would not help.
    #[test]
    fn only_the_http_transports_can_use_a_typed_credential() {
        assert!(credential_can_help("https://github.com/foo/bar.git"));
        assert!(credential_can_help("http://git.internal/foo/bar"));
        assert!(!credential_can_help("git@github.com:foo/bar.git"));
        assert!(!credential_can_help("ssh://git@github.com/foo/bar.git"));
    }

    /// The secret is read from the environment by the helper; it is never in argv, where `ps`
    /// would show it to any local user.
    #[test]
    fn a_typed_credential_is_answered_from_the_environment_not_from_argv() {
        let args = clone_args("https://github.com/foo/bar.git", Path::new("/tmp/bar"), true);
        assert_eq!(args[0], "-c");
        assert_eq!(args[1], "credential.helper=");
        assert_eq!(args[2], "-c");
        assert!(
            args[3].contains("DEEPSAND_GIT_SECRET"),
            "the helper reads the secret from the environment: {args:?}"
        );
        assert!(args.iter().all(|arg| !arg.contains("hunter2")), "no value belongs in argv");
    }

    /// With no credential typed, the machine's own helper and SSH agent are left to answer: that
    /// is the "default credentials" attempt.
    #[test]
    fn a_clone_with_no_credential_leaves_the_machines_own_helper_alone() {
        let args = clone_args("https://github.com/foo/bar.git", Path::new("/tmp/bar"), false);
        assert!(
            !args.iter().any(|arg| arg.starts_with("credential.helper")),
            "the machine's helper must still be tried: {args:?}"
        );
    }
}
