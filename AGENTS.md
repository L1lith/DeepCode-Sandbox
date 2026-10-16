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
| `npm run core:test` | `cargo test -p deepsand-core` — 374 tests |
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
* **A field the backend skips is absent from the payload, and a bound input renders that absence
  as the word "undefined".** Empty strings carry `skip_serializing_if`, so `AppSettings.user_prompt`
  was not in the JSON while it was empty -- and the text area bound to it showed that literal word,
  which the operator could then edit into their saved prompt. Mirror the skip as `?:` in
  `types.ts`, and read such a field as `?? ""` where it is rendered. Two hand-written halves of one
  contract will do this again: when a payload field is optional on one side, make it optional on
  the other in the same commit.

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
* **A debounce is a courtesy to the disk, never a licence to drop an edit.** The settings dialog
  saves as you type behind a 700 ms timer, and its cleanup used to do `clearTimeout(timer)` --
  cancelling the pending write when the dialog closed, which is precisely what somebody does with
  the last sentence they typed. The user prompt went missing every time that way, and the report was
  "it doesn't save when I shut down the program", which sent me looking at the state file (which was
  fine) and the backend round-trip (also fine) before the frontend. `flush()` now writes a pending
  edit on unmount, on `blur`, and on `pagehide`/`beforeunload`, and the write itself (`persist`) is
  split from the screen's signals so it can run while the dialog is being torn down. The same timer
  guarded the egress allowlist, so a typed host was lost the same way. Two things made this hard to
  see: nothing *failed* (there is no error in the log, because no request was ever made), and the
  state file is written by the backend, so it looked like a Rust problem. Reproduce UI-level
  behaviour through the running app instead of reading the JSX: `WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS=
  --remote-debugging-port=9222 npm run app:dev`, then drive the DOM over CDP -- a JS `click()` and a
  dispatched `input` event are delivered where synthetic mouse input is not.
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
* **A project's own `AGENTS.md` replaces the file Deepsand installs, so anything that must always
  reach the model cannot live only there.** `loadAgentInstructions` picks `<project>/AGENTS.md` or
  `<project>/.deepcode/AGENTS.md` when either exists and *only* falls back to
  `~/.deepcode/AGENTS.md` -- so the generated file is silently ignored in exactly the projects that
  ship one, which is most real repositories (three of four on this machine). The per-task playbook
  went into skills for this reason, and the operator's standing instructions go three ways at once,
  all resolved by `resolve_user_prompt`: into the generated file; into
  `SandboxSnapshot::user_prompt`, which the bridge puts in `deepsand_sandbox_info`'s description and
  result, where no file in the project can shadow it and the mount is `:ro` so the sandbox cannot
  forge it; and, when there *is* something to send and the project's own instructions shadow ours,
  into a generated `deepsand-operator-instructions` skill. No prompt means no skill: it exists to
  carry the operator's words, so `Off` -- or an empty box, wherever the text would have come from --
  writes none, and the writer removes the one it wrote before. It is written by
  `settings::operator_skill` into
  the config mount and installed by the entrypoint into `$DEEPCODE_DIR/skills/` -- the user-level
  root DeepCode scans that is also writable, since the rootfs is read-only -- and the entrypoint
  **removes that directory before installing it**, because the home volume outlives the setting and
  a skill left behind would go on instructing later sessions from a prompt that had been turned off.
  If you add a fourth place these are read from, they will drift, and the symptom is an agent that
  follows instructions in one repository and not in the next.
* **A named build context is not an image, and every build path has to supply it.** The tools layer
  mounts `from=toolcache`, which BuildKit resolves as a *stage* only because something passes
  `--build-context toolcache=…`. The app passes its keyed cache. `runtime/scripts/build-image.mjs`
  passed nothing, so a `npm run runtime:build` -- the command this file tells contributors to run --
  tried to pull `docker.io/library/toolcache:latest` and died with "pull access denied ...
  insufficient_scope: authorization failed": a registry message for a problem that was not the
  registry's. It now passes an empty directory, which the layer reads as "no cache" and installs the
  tools, and `every_build_path_supplies_the_toolcache_context` keeps both paths honest.
* **The window is told when a file it read once changes.** The host's DeepCode settings decide
  what "Defer to Config" resolves to, and the backend reads that file fresh on every use, so
  only the *window* can go stale -- which it did, showing a model from startup until it was
  restarted. `host_config.rs` polls it and emits an event that carries nothing: the views that
  depend on the file re-read it from the backend rather than being handed a second copy of the
  values. The poll compares a digest as well as a timestamp and a length, because a same-size
  edit inside one filesystem timestamp tick is otherwise invisible.
* **The tools cache is keyed by what changes the tools, and filled from a successful build.**
  `toolcache.rs` holds the two decisions that matter. *What* is cached: the compiled cargo
  binaries and the installed npm globals, because those are minutes of compiling and registry
  round-trips; not apt packages, because the build already has cache mounts for their downloads
  and moving installed system packages between images is the fiddliest thing here for the
  smallest gain. *When the key changes*: the platform, the sorted tool selection, a version
  constant, and a fingerprint of the tools layer's `RUN` -- not the whole Dockerfile, because
  the image tag already changes on every runtime edit and the tools must not be recompiled for
  a fixed comment. The cache is filled *from an image that built successfully*, never by a
  parallel install, so what is in it is what an image actually has; and a build that fails while
  using it drops it, so a bad entry heals itself. Freshness is the second half -- a key cannot
  see time passing -- so an entry older than `TOOL_CACHE_MAX_AGE` (two weeks) is emptied before
  the build, which installs the tools again and refills it. That is "up to date, only when
  necessary": immediate when the selection or the installer changes, fortnightly otherwise. The
  DeepCode CLI is exempt and refreshes on every build, bounded by npm's fetch limits and
  non-fatal when a copy exists, because for that one tool "latest" is the point. The cache is
  emptied *only* when a build that used it failed for a reason that is about the build -- a
  daemon that went away is neither the cache's fault nor the build's, and emptying on one of
  those would throw away minutes of compiling for nothing.
  **"There is a cache" means the marker and only the marker.** The app creates the entry's `bin/`
  and `node_modules/` before every build, because a build context has to exist, so a build that
  tests for those directories is testing something that is always true. That is exactly what the
  tools step did: it took the cached path on every build, installed nothing, and wrote a label
  naming every tool that was *asked for*. Images here were labelled `htmlq,puppeteer,wrangler`
  with none of the three in them -- confirmed against real images and reproduced with a build.
  `htmlq` is on by default, so this was every project, and the feature's own promise that "a bad
  entry heals itself" was false: an incomplete entry never failed, so nothing healed it. The
  app's rule is `toolcache::cache_is_usable` -- marker present and recent -- and
  `runtime_dockerfile.rs` now asserts that the build asks the same question. The npm globals are
  additionally asked of npm one at a time (`npm ls -g --depth=0`), because a marker can be right
  about the entry and wrong about one package, and a cache is an accelerator rather than an
  authority: that is what lets a partial entry heal itself instead of becoming an image that lies.
* **A label is a claim about the image, and a claim about the image has to be checkable.** The
  tools step ends with `LABEL deepsand.tools="$INSTALL_TOOLS"`, and that label is what
  `deepsand_sandbox_info` reports to the agent as the truth about what it has. So a build that
  skips an install does not merely produce a thinner image, it produces a sandbox that tells the
  agent it has a browser: the agent believes it, goes looking, and spends the turn finding out
  otherwise. Anything the sandbox says about itself has to be derived from what the build
  produced, or checked -- the way a claim about the *deployed* state belongs in a run rather than
  in prose.
* **A browser is four things, and three of them are silent when missing.** The `puppeteer` tool
  promises "a browser controlled from Node, with its own copy of Chromium". Being able to take a
  screenshot needs all of: the npm driver, the libraries a browser links against (`libnss3`,
  `libgbm1`, `libatk1.0-0`, `libcups2`, `libpango-1.0-0`, `libgtk-3-0` and the rest -- none are in
  the base image), an archiver to unpack the download (`unzip`: without it the browser downloads
  and cannot be extracted, and because that happens inside the package's own postinstall the error
  is *swallowed*), and the binary itself, in the cache of the user who will look for it
  (`PUPPETEER_CACHE_DIR=/home/deepcode/.cache/puppeteer`, owned by 1000, not root's home).
  Two traps worth remembering. The postinstall's half-finished download leaves a browser folder
  with no executable in it, and puppeteer then *refuses* to repair it -- "the browser folder exists
  but the executable does not" -- so the fetch starts by emptying the cache. And a browser keeps its
  own sandbox with user namespaces, which this container does not allow, so it must be launched with
  `--no-sandbox`; without it the failure is "Failed to launch the browser process" and nothing that
  explains why. All of this is now in the tools layer, gated on the tool id, and the build *fails*
  rather than shipping an image that claims a browser it does not have -- verified end to end here:
  as uid 1000, under Xvfb, puppeteer rendered a page and wrote a 10 KB PNG.
* **The tool check empties a cache entry; it never builds.** `tool_updates.rs` asks npm and
  crates.io what they offer for the versions a cache entry recorded when it was filled, and when
  something has moved it empties that entry -- the next *build* installs the tools again and
  refills it. It deliberately does not install anything itself: that needs Docker and an image,
  and a check on a timer has no business starting a build. Two rules keep it honest. A check that
  reached nothing is not a check, so it does not record one and the next cycle tries again rather
  than waiting out six hours. And what is compared is the listing the *tools* produced
  (`npm ls`, `cargo install --list`) at fill time, not what the cache was asked for, so a cache
  entry that disagrees with its own image is detectable rather than invisible. The DeepCode CLI
  is excluded on purpose: it is refreshed on every build already.
* **Hiding is only allowed when there is a way back.** Closing to the tray and starting in the
  background are one feature with the tray icon, not two: `tray::wanted` is the rule and the
  first thing its tests check, because a window that can vanish with no way back is a machine
  quietly running containers nobody can see. The difference between hiding and closing is one
  branch in `on_window_event`: hiding never runs `shutdown_cleanup`, so the sandboxes keep
  running -- which is the entire point of closing to the tray -- while the tray's Quit goes
  through the ordinary exit, so it does stop them. Startup has three modes rather than the
  boolean it replaced, and the boolean is still read: `start_at_login: true` becomes
  `Foreground`, which is what it meant, and the field keeps the old name as an alias so an
  existing state file is understood rather than silently ignored.
* **A build that stops talking is stopped.** The readers are blocked on the child's pipe, so
  the only thing that can interrupt a `docker build` which has stopped producing output is
  ending the process: `BUILD_SILENCE_LIMIT` (ten minutes of *silence*, not of elapsed time, and
  every slow step -- apt, npm, cargo -- prints as it goes) does exactly that, and the failure
  says how long it was quiet for rather than guessing that it hung. This exists because an `npm
  install -g` behind a connection that had stopped answering left an operator with a build that
  had simply stopped, and no way back except closing the app. npm's own fetch timeouts are
  bounded in the Dockerfile as well, so the common case fails in a minute instead of never.
  **The watchdog never `join`s**: it polls `try_wait` and leaves when the child is gone. Joining
  it was the first version, and it meant a build that had *finished* waited for the watchdog to
  notice the silence that followed it -- ten minutes of a progress bar frozen on the last step,
  which is precisely what the watchdog was written to prevent. A stop is the operator's to ask
  for as well: `cancel_build` finds the build by tag in `LIVE_BUILDS` and ends it, and the
  failure says it was stopped rather than broken.
* **A preflight is bounded by a healthy answer, not by the command timeout.** The host-sharing probe
  runs while the operator watches "Starting…", and it used to inherit `COMMAND_TIMEOUT` (120 s) for
  every step -- `create`, `cp` and two `rm`s, on up to two candidate images, per mount. On a machine
  whose file-sharing layer had stalled that was minutes of nothing: measured here, a `docker cp` of
  one small file out of a bind mount answers in **0.16 s** when the layer is healthy and took **three
  minutes** when it was not, with `version`, `images` and `create` answering instantly throughout. It
  now runs on `SHARING_PROBE_LEASH` (15 s, ~90x a healthy answer), stops at the first silence instead
  of spending the leash again on the other image, and cleans up on its own short leash. The verdict
  is typed -- `ProbeStep::Silent` versus `Answered(Err(..))` -- rather than read back out of a
  sentence, because the two lead to different next steps: a refusal is worth the other image, silence
  is worth nothing at all. Silence sets `runtime_wedged`, so the window offers the restart instead of
  showing a directory problem with nothing to press; `docker_status_watched` clears it when Docker
  recovers. Two smaller things from the same afternoon: the probe container now carries
  `LABEL_MANAGED`, without which `prune_orphans` could not see the three left behind by one stalled
  probe, and `sessionOperation` re-reads the docker status when an operation fails, because a start
  that failed is exactly when the answer may have changed.
* **When Docker Desktop is unwell, Deepsand says so and offers the restart -- it does not restart it
  itself.** Restarting it ends *every* container on the machine, including work that has nothing to
  do with Deepsand, so the decision is the operator's; an automatic restart was built and removed for
  that reason. What the app owes the operator instead is that the control is actually *in front of
  them*: the start records the verdict in `runtime_wedged`, `docker_status_impl` turns that into
  `available: false` with the "its container runtime is not answering" detail, and the window's
  callout then shows `RestartDockerControl` -- which restarts Docker Desktop *and* retries the start
  (`restartDockerAndRetry`). The two things that used to break that chain were both silent: the
  sharing probe did not set the flag at all, so the runtime looked fine and no button appeared, and
  the window did not re-read the status after a failed operation, so it went on showing the stale
  "Docker is fine". Any new failure that means "Docker, not this project" has to do both.
* **Nothing this app starts outlives it.** Windows does not end a child when its parent exits,
  and `std::process::exit` in the shutdown path abandons whatever is still running: a hung
  `docker build` was found an hour and a half after the app had gone, still holding the image
  tag it was building, which is what the *next* build waits for. `docker::terminate_our_clients`
  asks the operating system for this process's own children by name (`docker*`) and ends them,
  and it is called at the start of `shutdown_cleanup` -- before the polite work, because the
  polite work is what has a budget and can be abandoned.
* **Attaching is the operator's action, and it is bounded.** Pasted or dropped files are copied
  into the sandbox's own `~/.deepcode/attachments` -- never into the workspace, which is the
  operator's repository -- and are size-capped on both sides. A path already inside the
  workspace is *named* rather than copied, but only after `canonicalize`, so a symlink cannot
  pretend to be inside it. One file failing is reported without losing the others: attaching
  three and dropping all three because the fourth was a directory is worse than three and a
  reason. The paste path is captured on the terminal's host element before xterm's own listener,
  because text paste already works and only a clipboard with *files* needs intercepting.
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
* **A terminal resize is not a no-op, so never send one twice.** A window-change makes a
  full-screen TUI inside the sandbox paint everything it has, so a window that re-fits on every
  layout pass and tells the sandbox each time turns a layout pass into a repaint of the whole
  session. That is the failure where the terminal appears to scroll itself over and over, far too
  fast to read, and will not stay still long enough to scroll up in. Both halves are guarded:
  `TerminalPane`'s `safeFit` measures with `proposeDimensions` and does nothing when the size is
  what xterm already has (coalesced to one fit per frame, because a fit inside a `ResizeObserver`
  callback is a layout change reported back to that observer), and `Session::resize` drops a size
  the PTY already has via `resize_is_needed`, which also floors a zero-sized pane at 1×1 rather
  than resizing to nothing. Guarding only the window is not enough: the leak that matters is the
  one you did not think of.
* **An egress-proxy test must not read the connection to the end.** The proxy answers a
  tunnel with `200 Connection Established` and then relays, so the connection closes when
  the *far end* closes it: measured here, GitHub at 91 s and Cloudflare at 15 s, which is
  where 170 of this suite's 175 seconds went. Read until a quiet period instead, and bound
  the upstream attempt in the proxy itself (`ProxyConfig::upstream_timeout`, which covers
  resolution as well as connect) rather than relying on the network to answer promptly.
* **MCP `tools/call` is capped at 60 s.** The bridge waits ~45 s and then replies
  `PENDING` with a request id; the model collects the answer later with
  `deepsand_check_request`. Do not make the bridge block indefinitely.
* **A permission dialog freezes the sandbox, and freezing does not stop the clock.** While the
  operator has a request in front of them the container is `docker pause`d, so the agent cannot
  work ahead of a decision it has not been given; the broker watcher reconciles that against the
  pending set every 400 ms through `docker::freeze_transition`, which answers `None` unless the
  answer changed (a `docker` call is 180-600 ms, so a level-triggered version would spawn one per
  tick). DeepCode's 60 s budget is a `setTimeout` inside the *frozen* process, and a timer counts
  down in real time whatever its process is doing: a decision that takes longer than that ends
  the tool call the agent was waiting on, which is why `deepsand_list_requests` exists -- it names
  each request and what it was for, so a model that never saw the id can still collect the
  decision. Two rules come with it. Every removal thaws first (`container_teardown_args`), because
  a frozen container refuses `exec` and cannot take a signal; and nothing may be left frozen when
  the app goes away, so `stop_session_internal` thaws and clears, and an orphan sweep at startup
  removes whatever a crash left behind.
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
