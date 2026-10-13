# AGENTS.md

How to change **Deepsand itself** — a Tauri desktop app that runs the DeepCode
CLI inside a Docker container it cannot escape.

This file is for anyone, human or agent, editing this repository. It is not the
document the contained model receives; that one is generated per project at run
time. See [Two AGENTS.md files](#two-agentsmd-files) before you confuse them.

## Get running

```bash
npm install
npm run runtime:build   # build the sandbox image (once, ~3 min, needs Docker)
npm run app:dev         # app with hot reload
```

`npm run runtime:build` needs Docker running. `npm run core:check`,
`npm run core:test` and `npm test` do not — the Rust tests never call Docker.

## Commands

| Command | What it does |
| --- | --- |
| `npm run app:dev` | Tauri app with hot reload |
| `npm run app:build` | platform installer |
| `npm run core:test` | `cargo test -p deepsand-core` — 347 tests |
| `npm run app:test` | `cargo test -p deepsand-app` — the app crate's own tests, including the zombie guard. Part of `npm test`: it was not, and tests that never run are decoration |
| `npm run core:check` | `cargo check --workspace` |
| `npm run test:bridge` | 55 checks of the MCP bridge against a simulated spool |
| `npm test` | the two suites above, in order |
| `npm run build` | `tsc --noEmit` + `vite build` (frontend typecheck) |
| `npm run runtime:build` | build and tag the sandbox image |
| `npm run runtime:icons` | regenerate `src-tauri/icons` from `assets/icon.png` |

## Where things live

| Path | Responsibility |
| --- | --- |
| `crates/deepsand-core/src/paths.rs` | Canonicalises a path, then guards it. Symlinks are resolved **before** any check. |
| `crates/deepsand-core/src/policy.rs` | Builds the one and only `docker run` argv, and audits the mount list. |
| `crates/deepsand-core/src/store.rs` | Projects, grants, and the atomic-write state store. |
| `crates/deepsand-core/src/broker.rs` | Watches the request spool, validates hostile input, surfaces prompts. |
| `crates/deepsand-core/src/proxy.rs` | Allowlist egress; resolves names itself and refuses private results. |
| `crates/deepsand-core/src/secrets.rs` | ChaCha20-Poly1305 secrets, keyed from the OS keystore. |
| `crates/deepsand-core/src/tools.rs` | Tool catalogue and the image tag a selection produces. |
| `crates/deepsand-core/src/remote.rs` | What a remote client may do. Kept separate from HTTP so it is testable. |
| `crates/deepsand-core/src/seccomp.rs` | The profile's digest, the runtime-tree resolver, and the check that the applied profile is the shipped one. |
| `crates/deepsand-core/tests/seccomp_profile.rs` | Claims about the profile itself: address families, `CLONE_NEW*` bits, the ptrace family. Reads the repo artifact, so no Docker needed. |
| `crates/deepsand-core/src/bin/deepsandctl.rs` | Headless driver: `doctor`, `project`, `grants`, `plan`, `run`, `watch`, `requests`, `network`. |
| `src-tauri/src/commands.rs` | The ~30 desktop commands, and `runtime_revision`. |
| `src-tauri/src/remote_server.rs` | HTTP translation of the command surface. Binds loopback, bearer token. |
| `src-tauri/src/update.rs` | Self-updates: the check, the download, the restart. Our own commands, not the plugin's JS bindings. |
| `.github/workflows/release.yml` | Cross-platform release builds and the update manifest. Publishes a **draft**. |
| `src/` | SolidJS UI. Views only: no policy decisions. |
| `runtime/` | Everything that runs **inside** the container. |

## The invariants

These are load-bearing. Breaking one is how this project gets a CVE.

1. **Policy lives in `deepsand-core`, never in the GUI or the Tauri layer.** If a
   question is "should this be allowed", it belongs in `paths.rs` or `policy.rs`.
   That is what keeps the desktop app and `deepsandctl` from drifting apart, and
   it is why a reviewer can read the whole boundary in a few files.
2. **`policy::plan_run` is fail-closed.** It returns an error rather than a
   weaker plan. Hardened seccomp missing, a writable reply channel, a mount list
   that does not look right — all of those are errors, not warnings. Never add a
   fallback that starts the container anyway.
3. **The sandbox can ask; it can never answer.** The response spool and the state
   directory are mounted `:ro`. A change that makes either writable is a privilege
   escalation, not a feature.
4. **Only `/workspace` and grants are mounted from the host.** `audit_mounts`
   rejects anything else, including container-runtime sockets by name.
5. **`runtime_revision` must cover every image build input.** It hashes
   `runtime/bin/*`, `Dockerfile`, `seccomp-hardened.json`, `gitconfig` and
   `runtime/skills/*/SKILL.md`. Add a file the image is built from and you must add
   it there too, or the tag stops changing and the image silently goes stale. This
   already happened once with the seccomp profile.
6. **Secrets go through `--env-file`, never `-e`.** `docker run -e NAME=value`
   puts the value in the process argument list, where any local user can read it
   with `ps`. A test asserts no value-shaped `--env` pair can appear in a plan.
7. **Credentials and generated config go to Deepsand's data directory, never into
   the user's project.** Project directories get committed, published and synced.
8. **The profile that gets applied must be provably the profile the image carries.**
   The daemon resolves `--security-opt=seccomp=` on the *host*, so the image's copy
   is only ever read by an auditor. The Dockerfile writes the profile's digest beside
   it and `seccomp::verify` compares the two before anything starts, refusing on a
   mismatch, a missing digest or a malformed one. `seccomp::runtime_dir()` is the
   single resolver for the runtime tree — do not add a second search order, which is
   how the applied and shipped profiles drifted apart once already.
9. **The request spool is not authenticated, and cannot be.** The bridge is a child
   of the agent's own process as uid 1000, so any secret it can read the agent can
   read. Do not add a token, nonce or pid check to a request expecting it to be a
   control: it will be forgeable, and a credential-shaped field that authenticates
   nothing is worse than no field. The human decision is the control — which means
   **never add an auto-approve path** ("already granted", "approved before"), because
   that converts dialog spoofing into a silent host-directory grant.
10. **An allowlist entry's shape decides how it is enforced, and only an address
    entry may bypass the proxy.** A hostname entry goes through the egress proxy,
    which is where the path rules and the DNS-rebinding refusal live; an address
    entry is allowed directly by the container's own rules, so a database client
    that speaks no HTTP can reach it. Do not "simplify" this by resolving hostname
    entries into direct rules: that would re-open the rebinding hole the refusal
    exists for. A port named in an entry is also published on the host's
    **loopback**, never on `0.0.0.0`.
11. **Never auto-approve a permission request; auto-refusal is allowed only when
    there is nothing left to decide.** `covered.rs` refuses a request for something
    the sandbox already has (a directory inside `/workspace` or a grant, a host
    already on the allowlist, an installed tool) and says where it already is. That
    is a `deny`, because an automatic `allow` is consent the operator never gave.
    Anything ambiguous — a wildcard pattern, a write request against a read-only
    grant, `locate_resource` — must reach the operator. The same path answers a
    project whose `requests_enabled` is false, and **that check must live on the
    host, not only in the bridge**: the bridge is the agent's own child process, so
    its copy of the flag saves a wasted tool call and decides nothing.
12. **LF line endings for everything Linux reads or executes.** `.gitattributes`
    enforces this. A shell script with a CRLF shebang fails inside the container
    with `bash\r: No such file or directory` and the sandbox never starts.
13. **A state file that cannot be read is not a state file that is corrupt.** The
    distinction is the difference between losing an operator's projects and not:
    `ReadOutcome::Unreadable` is retried and then reported, and the file is left
    alone; only `Corrupt` is moved aside. Two rules go with it. A store built
    because nothing could be read (`Store::fallback`) must never rotate the rolling
    backup, because its state is a substitute and promoting a substitute destroys
    the last good copy. And a set-aside copy with projects beats an empty fallback,
    because an empty answer is far more likely to be wreckage than an operator with
    no projects left. All four are asserted in `store::durability_tests`; a replay
    against a real data directory is what caught the empty-backup case, so run the
    tests against real data when the failure being fixed was real.
14. **The state file must stay readable by older builds, because the installed app
    and a development build share one data directory.** An older build cannot read a
    serde variant or field it has never heard of, and it reports the whole file as
    corrupt -- set aside, empty project list. That cost an operator five projects,
    twice. So: widen the stored shape only additively, and where a name changes,
    **write the older spelling** (`NetworkPolicy::Allowlisted` is stored as
    `restricted` for exactly this reason) and accept both on load. A file that this
    build cannot map is a version skew, not damage: `ReadOutcome::Incompatible`
    reports it and leaves it alone, and a file whose `version` is newer than
    `STATE_VERSION` is refused rather than loaded and silently downgraded on the
    next save. And do not point newer tooling at the live data directory of an
    older install -- `deepsandctl --data-dir` writes, and it rewrote this one.
15. **`reference/` is never committed, vendored or bundled.** Upstream DeepCode CLI
    source is downloaded there read-only, and gitignored.
16. **The update signing key never enters the repository, and its loss is
    permanent.** The private half lives in `~/.tauri/deepsand.key` and in the
    `TAURI_SIGNING_PRIVATE_KEY` secret; the public half is pinned in
    `src-tauri/tauri.conf.json`, which is what every installed copy verifies
    against. Whoever holds the private key can sign an update that all of them
    will install, and losing it means no installed copy can ever be updated.
    `.gitignore` covers `*.key` as a backstop, not as permission to be careless.
17. **The three version fields move together** — `src-tauri/tauri.conf.json`,
    `package.json`, and `version` in the workspace `Cargo.toml`. The release
    workflow fails early when they disagree, because a release whose manifest
    version is wrong tells every installed copy it is already up to date: a
    silent failure where nobody gets an error and nobody gets the update.
18. **The updater is reachable only through our own two commands.** The plugin is
    initialised in Rust and the webview is not given `updater:*` — installing an
    update replaces the binary, which is the most powerful thing a frontend could
    ask for. The commands are absent from the remote command table on purpose: a
    remote client must not be able to replace the binary on the host it reached.

## Conventions

* **Tests are named as claims.** `a_plan_never_mounts_a_container_runtime_socket`,
  `the_reply_channel_can_never_be_written_by_the_sandbox`,
  `the_seccomp_profile_is_attached_even_on_docker_desktop`. Keep that style: the
  test names *are* the security argument, and `docs/SECURITY.md` cites them.
* **Do not state a claim in `docs/` that no test asserts.** A previous round of
  this project asserted a control was in place without running the check that
  would have shown it was not. If a claim is about the deployed state — what the
  container actually got — it belongs in a run, not only in prose.
* Rust 2021, `rust-version = "1.82"`. Errors are `thiserror` in the core,
  `anyhow` at the edges.
* The frontend is **SolidJS**, not React. Signals, not hooks: do not reach for
  `useState`/`useEffect`.
* `src/lib/types.ts` mirrors the Rust payloads in `src-tauri/src/state.rs` by
  hand. Serde uses camelCase; the enums keep their own shape. Changing one side
  means changing the other.

## Platform quirks that will cost you an afternoon

* **`CAP_DAC_OVERRIDE` is absent inside the entrypoint** (`CapEff` is `0xc1`:
  `CHOWN`, `SETUID`, `SETGID`). Root is still bound by permission bits, so
  "`chown` a directory to uid 1000, then write into it as root" fails with
  `EACCES`. The ordering in `runtime/bin/entrypoint.sh` is load-bearing: create,
  take ownership, copy, then hand over. Because Docker Desktop's volume driver
  also refuses `chmod` on a volume mount root, the entrypoint verifies the
  property that matters (uid 1000 can read its credentials and write its volume)
  and stops with an explanation instead of assuming.
* **One build per image, one writer per log.** Everything that builds goes through
  `build_runtime_image_impl` -- the Activity tab's button and a Run whose image is missing --
  and it claims the image in `AppState::building` first. A second caller *waits*; a second
  *writer* is how the build log came to hold two copies of the same RPC error at different
  offsets with a gap of NULs between them, which is what a write at somebody else's file
  offset looks like. If you add another way to build, put it behind that claim.
* **Build output is read through `docker::sanitize_output_line`.** A read from a dying
  daemon's pipe can come back zero-filled, and `BufRead::lines` hands that back as one line
  of 32 KiB of NULs: the log from that failure is 302 bytes of output followed by 32,289
  NULs. The filter cuts a line at its first NUL, drops control characters, drops a line that
  is only them, and truncates at 4 KiB. It is applied where lines are handed out, so the
  tail, the window and the log all see the same text. Anything that reads a pipe needs this
  reasoning: NULs are not content, they are a read that did not happen.
* **A build failure is classified before it is reported.** `docker::is_daemon_interruption`
  separates "the daemon went away" from "the Dockerfile is wrong", because the responses are
  opposite: the first is waited for and retried once (the layer cache survives it), the
  second is read. Reporting the first as the second is how an operator ends up checking
  their Dockerfile for a fault that is Docker Desktop restarting.
* **The window is the app's lifetime, and the shutdown is bounded.** `shutdown_cleanup`
  runs when the window is destroyed, on the UI thread, and it shells out to Docker. Nothing
  on that path may be unbounded: with Docker Desktop restarting under it the call never
  returned, the process sat there with no window and a blocked event loop, and -- because the
  single-instance plugin hands every later launch to whatever process already exists -- the
  app then looked like it would not start at all. It is given ten seconds and the process
  exits either way.
* **One instance, and a stuck one must not swallow a launch.** `instance.rs` holds a lock
  file for the life of the process, writes a record of itself, and proves it is alive with a
  heartbeat scheduled through `run_on_main_thread` -- so the proof comes from the *UI thread*
  and a stuck event loop stops beating. `instance::decide` is the whole rule, and it is
  tested: beating -> hand the launch over; stopped beating with a window -> leave it alone
  (the operator can see it); stopped beating with no window -> clear it and start. A launch
  must never be silently swallowed by a process that cannot show anything.
* **A status the window shows has to be re-read where it can change.** `app_info`
  deliberately carries no Docker status -- probing there put three Docker CLI calls in front of
  the first paint -- so re-reading it means calling `docker_status`. `refreshSettings` used to
  be the thing that refreshed Docker, and when the field left `app_info` the compiler could not
  see across the TS boundary: the announcement of a change arrived and nothing was re-read, so
  the app went on saying the daemon was unreachable with Docker plainly running. Worse, a "no"
  was kept forever: the probe runs once, after the window is ready, which is routinely while
  Docker Desktop is still starting. It is retried while the answer is no, and re-asked when the
  window takes focus. If you move a field out of a command, grep the frontend for it.
* **One piece of in-flight state, and it always lets go.** Whether a session operation is
  running lives in the store (`sessionBusy`), not in each component: the header's Run and the
  terminal's Run each had their own signal, so one could be left greyed out for the rest of the
  session while the other was fine. `sessionOperation` also has a ceiling, because `finally`
  releases the button whenever a promise settles -- which is every outcome except the promise
  never settling, and a backend that never answers must not be able to lock the operator out. A
  disabled button says what it is waiting for ("Starting…"): a grey button with no text cannot
  be told apart from a broken one.
* **Anything signed with the API key happens in the app, never in the window.** The model list
  is fetched in `src-tauri` with the project's resolved credentials, and the frontend receives
  ids and names -- never a key, not even masked. The cache that keeps the list between projects
  digests the key rather than storing it, and a failure to list comes back as a `problem` string
  rather than an error, so the dropdown still offers the two choices that need no list at all.
* **A per-project model is `credentials.model`, and `None` means "defer to configuration".**
  One field, so the header dropdown and the project's own credentials cannot disagree, and
  clearing the choice puts the configured model back rather than leaving the last one behind
  (`a_projects_own_model_wins_and_having_none_defers_to_configuration`).
* **Contents before name.** Anything that holds state is written to a sibling file, synced
  with `sync_all`, and only then renamed over the real one. A rename is atomic but not durable
  on its own: without the sync, a crash can commit the name and lose the data, which is how
  this machine was left with an 18,412-byte `Dockerfile` of NULs and a `state.json` of them
  twice. The build log is synced before its outcome is announced, because its job is to be read
  after a failure -- including one that takes the machine with it.
* **A reader treats a file with NUL bytes in it as damage, never as content.** That is the
  shape this failure takes, and a reader that shows it is worse than one that shows nothing:
  log lines, audit lines and runtime files are all filtered this way. `store.rs` keeps a dated
  copy of the configuration once a day for the case where the live file *and* its rolling
  backup go together, which one crash can do -- written only when there is a project worth
  keeping, so an empty state cannot hold the day's slot.
* **The runtime files are read from disk, so they are checked before they are used.** A
  machine that loses the contents of a write while keeping its size leaves a `Dockerfile` of
  NULs, and Docker's answer to that -- `dockerfile parse error on line 1: unknown instruction:`
  -- names nothing an operator can act on. `runtime_files` embeds every file under `runtime/`
  (there is a test that the list is the whole tree, so a new file cannot be forgotten) and
  repairs only what is *not text*: NULs, empty where content belongs, or missing. A file that
  merely **differs** is an edit or another build's tree, and is never touched -- overwriting
  those would be a much worse bug than the one being repaired. The build path repairs and says
  which files it replaced; `deepsandctl doctor` reports the state without writing anything.
* **When something is unreachable, say which part.** Docker Desktop running with a daemon that
  is not answering is not the same situation as Docker Desktop not running, and they get
  different sentences (`docker::unreachable_detail`, chosen by asking whether the Desktop
  processes exist -- only on the failure path, where the answer changes what to say). Telling
  an operator to start what they can see running is how a correct message gets ignored.
* **An error the operator can see is written down.** Every box the window raises with
  `toast("error" | "warn", ...)` goes to the log, every failed command is logged with its own
  name by `api.ts`, and so are the startup notice and the screen for a window that could not
  start. Three separate paths on purpose: the box carries the text the operator read, the
  command line says which call failed (including the ones the window swallows), and the fatal
  path has no box to carry anything. If you add a surface that shows an error, put it through
  `toast` or log it yourself -- the log is the only place a message survives the window.
* **An error box is not dismissed by a click.** A click is how a person starts selecting the
  text, and being gone by then is why messages could not be copied. Errors therefore stay
  until they are closed, show their body whole, and have a Copy button; the others still
  disappear on a click, which is what keeps them unobtrusive.
* **Anything the app says about itself goes in a file.** A Windows release build has no
  stdout, so `tracing` output went nowhere: a launch that died silently stayed silent, with
  nothing to read on the machine where it happened. `init_logging` tees to
  `data_dir/deepsand.log` (rotated at 2 MB, one previous kept) and installs a panic hook. The
  log carries ids, addresses and errors, never credentials. Anything that can fail early --
  before there is a window to report in -- has to say so there.
* **Nothing on the first-paint path may call Docker.** Every `docker` invocation spawns
  the CLI, which costs 180-600 ms on this machine, so a probe is user-visible time. A probe
  was 1549 ms: five sequential calls for two versions, two `info` fields and an image
  inspect. It is now three concurrent calls (`version --format '{{json .}}'`,
  `info --format '{{json .}}'`, `image inspect`) and costs 379 ms measured, and `app_info`
  -- the window's first call -- no longer probes at all: it returns `docker: null` and the
  window asks with `docker_status` once it is up, drawing "Checking Docker…" until then.
  The startup sweeps (orphan cleanup, the availability poll) wait two seconds so they do not
  race the window for the same CLI. If you add a startup path, ask whether the first paint
  needs the answer; if it does not, do not ask the question there.
* **An egress-proxy test must not read the connection to the end.** The proxy answers a
  tunnel with `200 Connection Established` and then relays, so the connection closes when
  the *far end* closes it: measured here, GitHub at 91 s and Cloudflare at 15 s, which is
  where 170 of this suite's 175 seconds went. Read until a quiet period instead, and bound
  the upstream attempt in the proxy itself (`ProxyConfig::upstream_timeout`, which covers
  resolution as well as connect) rather than relying on the network to answer promptly.
* **MCP `tools/call` is capped at 60 s.** The bridge waits ~45 s and then replies
  `PENDING` with a request id; the model collects the answer later with
  `deepsand_check_request`. Do not make the bridge block indefinitely.
* **Bind mounts cannot be added to a running container.** An approval recreates
  the container and resumes the session from the named volume. DeepCode's
  `--last` calls `process.exit(1)` when there is no session, so the session index
  is verified in the volume before `--last` is used. A grant inside a
  pre-declared `allowed_roots` entry is the exception that skips the restart
  (the core supports it; the UI does not expose it yet).
* **Windows specifics.** The terminal is a real ConPTY via `portable-pty`. When a
  command passes Windows-style paths or `/`-prefixed arguments through this
  shell, set `MSYS2_ARG_CONV_EXCL='*'` or msys rewrites them.
* **Release profile is `panic = "abort"`**, so no unwinding: a panic takes the
  process down. Prefer returning `Result` at the edges.
* **`lto = true` with `codegen-units = 1` makes the link the cost of a release
  build.** That is the right trade for a shipped binary and the wrong one for a
  local loop, which is why `app:build:debug` and `app:build:fast` exist.
  **The linker is not the lever, and that is measured, not assumed.** A release
  relink of `deepsand-app` after touching one file takes 219 s with the MSVC
  `link.exe` and 212 s with `rust-lld` — 3%, which is noise. With `lto = true` the
  time is LLVM optimizing across every crate *before* any linker runs, so swapping
  the linker cannot help. Do not spend an afternoon on it twice. The lever is LTO
  itself: turn it off for local builds, which is what `app:build:fast` does. Note
  that changing any of this changes cargo's fingerprints, so the first build after
  such a change recompiles everything — including in CI, where it costs one cache
  miss on the next release. Changing `RUSTFLAGS` does the same.
* **One image tag, derived in one place.** The `image` in settings is a *stem*: the tool
  selection and the runtime revision are appended to it, so the stem is not what any project
  runs. `settings::settings_for_project` is the only place that substitution happens, and
  every caller that builds a plan goes through it. This was wrong for a while in the most
  expensive way: two call sites derived the tag, one was forgotten, and the plan named the
  stem while the app built, labelled and digest-checked the derived tag -- so the selected
  tools were never in the sandbox and the revision that forces a rebuild never reached a
  container. If you add a plan path, add a test that the argv names the project's tag.
  `deepsandctl plan <project> --offline` prints the argv without touching Docker, which is
  how this was caught.
* **The image's slow step depends on the tool selection, not on the app.** The
  tools layer (`apt` plus `cargo install`, e.g. htmlq) is ~70 s and only rebuilds
  when a project's tools change; the DeepCode layer rebuilds on *every* image build
  because the app passes a fresh `DEEPCODE_REFRESH`. Both are covered by BuildKit
  cache mounts for apt's lists/archives and npm's cache, which is why the apt
  branches must not `rm -rf /var/lib/apt/lists/*` any more: that would empty a cache
  rather than shrink a layer. Cargo's registry is deliberately *not* mounted — the
  tools step deletes `$CARGO_HOME`, and deleting a mounted path fails the build.
* **Moving or renaming the checkout needs `cargo clean`, and that includes the
  release profile.** Two things bake the absolute path of the working directory into
  build output: `env!("CARGO_MANIFEST_DIR")` in the test that reads
  `runtime/seccomp-hardened.json`, and Tauri's generated permission files under
  `target/<profile>/build/tauri-*/out/`. After a rename the stale binary or build
  script looks in the old directory and fails with `os error 3` and a path you no
  longer have. `cargo clean -p tauri -p tauri-build -p deepsand-app` covers the
  second in **both** profiles; touching the file covers the first. Do it before the
  first build after a move, not after: `tauri build` otherwise fails at the *end* of
  a long release build, which is where this note's second sentence comes from.

## Definition of done

```bash
npm run core:check
npm test
npm run build
```

If you touched `runtime/`, re-read invariant 5 and check `runtime/README.md` —
the image is only rebuilt when its revision hash changes. If you changed the
permission protocol, `runtime/bin/deepsand-mcp-bridge.mjs` and
`crates/deepsand-core/src/broker.rs` have to move together; the two facts worth
preserving are that the bridge writes requests atomically and that the answer
directory stays read-only.

## Two AGENTS.md files

| File | Audience |
| --- | --- |
| `AGENTS.md` (this file, repository root) | Contributors and coding agents changing Deepsand. |
| The generated `config/AGENTS.md` | The model running **inside** the sandbox. |

The second one is produced by `crates/deepsand-core/src/settings.rs` for every
project, installed into the container at `/etc/deepsand/AGENTS.md`, and copied to
`$HOME/.deepcode/AGENTS.md` where DeepCode loads it automatically. It tells the
contained model what it can currently reach and how to ask for more. Changing how
the sandbox behaves means editing that generated text, not this file.
