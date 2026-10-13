<div align="center">

# Deepsand

**Run [DeepCode](https://github.com/lessweb/deepcode-cli) inside a container it cannot escape.**

Deepsand is a desktop app that gives each project its own Docker-contained DeepCode instance. The container sees the project directory and whatever you explicitly share with it — nothing else. When DeepCode needs more, it has to ask, and you decide.

</div>

---

## What it does

Create a project, name it, point it at a working directory:

```
┌─ Deepsand ──────────────────────────────────────────────────────────────┐
│  Projects            │  my-website                                      │
│  ▸ my-website  ●run  │  D:\work\my-website → /workspace                 │
│  ▸ api-server        │  [Terminal] [Permissions 2] [Tools]              │
│                      │  [Secrets] [Activity]                            │
│  [+ New project]     │   Deep Code  v0.4.3                              │
│                      │   > add a dark mode toggle to the header         │
│                      │                                                  │
│                      │   ● DeepCode is trying to access                 │
│                      │     C:\Users\me\Documents\brand                  │
│                      │     [Deny]  [Grant access]                       │
└─────────────────────────────────────────────────────────────────────────┘
```

Press **Run** and Deepsand:

1. builds one `docker run` command (you can read it in full — see the Activity tab),
2. starts the DeepCode CLI inside it under a real PTY, which the terminal pane renders,
3. answers any permission request DeepCode makes by asking you first.

## The two questions DeepCode can ask you

DeepCode knows it cannot see everything, and it has an API for saying so:

| It says | You get |
| --- | --- |
| *"I need `C:\Users\me\Documents\brand`"* | **"DeepCode is trying to access C:\\Users\\me\\Documents\\brand"** with that exact path shown, read-only pre-selected |
| *"I need the my-website repo — but this sandbox can't tell me where that is"* | **"DeepCode is requesting access to the my-website repo"** with a folder picker, because only you know where it lives |

Approving recreates the container with the new mount attached and resumes the
session, so the conversation continues where it left off. Denying is final and
DeepCode is told so.

## What you control per project

Every project carries its own policy, so a throwaway repository and a client
codebase do not have to share one.

| Setting | Where | Notes |
| --- | --- | --- |
| Network mode | `deepsandctl network <project> <mode>`, with the app-wide default in **Settings** | `internet` (default), `restricted` with a hostname allowlist, `none`, or `full`. |
| DeepCode mode | Project settings | `strict` additionally makes DeepCode prompt for network, MCP and out-of-workspace access in the terminal, on top of the container boundary. |
| Tools | Tools tab | Per-tool switches, plus **Enable all** / **Disable all** for each section and globally. The selection decides how the image is built, so the next Run rebuilds it — with its progress shown. |
| Thinking intensity | Tools tab | `none` / `low` / `high` / `max`, or deferring to your host `settings.json`. Pushed into a running sandbox as well as saved for the next start. |
| Secrets | Secrets tab | Per project. Encrypted at rest with the operating system's keystore, injected as environment variables at start. Values travel one way only: the interface shows names and lengths, never the value. |
| Limits | Project settings | Memory, CPUs, pids. |
| Credentials | Project settings | Inherit your host DeepCode configuration, or give this project its own model, base URL and key. |

## Install

Requires **Docker Desktop** (or Docker Engine on Linux) and, to build from
source, **Node.js ≥ 22** and **Rust ≥ 1.90** — the self-updater plugin is what sets
that floor.

```bash
git clone https://github.com/L1lith/Deepsand
cd Deepsand
npm install

npm run runtime:build     # build the sandbox image (once, ~3 min)
npm run app:build         # produce the installer for your platform
```

For development, `npm run app:dev` starts the app with hot reload.

A local release build signs its update bundles, so it needs the key in the environment or
it stops with an error about updater artifacts. `TAURI_SIGNING_PRIVATE_KEY` may be the key
itself or a path to it:

```powershell
$env:TAURI_SIGNING_PRIVATE_KEY = "C:\Users\you\.tauri\deepsand.key"
npm run app:build
```

```bash
export TAURI_SIGNING_PRIVATE_KEY=~/.tauri/deepsand.key
npm run app:build
```

> `npm run runtime:build` uses `runtime/Dockerfile`, which installs
> `@vegamo/deepcode-cli` from npm. Set `DEEPSAND_BUILD_TOOLS=1` in
> `DEEPSAND_BUILD_ARGS` if you want compilers inside the sandbox as well.

### First run

Deepsand reads your existing DeepCode configuration for the model, base URL and
API key:

```
~/.deepcode/settings.json          (Linux/macOS)
%USERPROFILE%\.deepcode\settings.json   (Windows)
```

If that file does not exist, set the values per project under **Project
settings → Model credentials**. The key is copied into Deepsand's own data
directory and injected into the sandbox at start; it is never written into your
project.

## Headless use

The desktop app is a shell over `deepsand-core`, and everything is available
without a display:

```bash
deepsandctl doctor                          # Docker, image, credentials, hardening
deepsandctl project add my-website D:\work\my-website
deepsandctl plan my-website                 # print the exact docker run command
deepsandctl run my-website                  # attach the sandbox to this terminal
deepsandctl watch my-website                # in a second terminal: be the broker
deepsandctl grants my-website add D:\work\brand --purpose "site palette"
deepsandctl network my-website restricted
```

`deepsandctl plan --offline <project>` prints the command and the generated
configuration without needing Docker running, which is the easiest way to review
what the sandbox will be.

## How the containment works

The container has **no reference to the host filesystem** other than the mounts
Deepsand chose. That is the whole guarantee — everything else is defence in
depth.

* **Mounts.** `/workspace`, the directories you granted (under `/grants`, `:ro`
  unless you said otherwise), Deepsand's own generated config and state
  (`:ro`), a write-only request spool, and a named volume for session history.
  Nothing else. No home directory, no `/var/run/docker.sock`.
* **Privileges.** The entrypoint runs as root just long enough to install egress
  rules and adopt a volume, then drops every capability, the bounding set and
  uid 0. DeepCode runs as uid 1000 with `--read-only` and
  `--security-opt=no-new-privileges`.
* **Network.** Default is **allowlisted**: an allowlist through a filtering proxy,
  plus any address you name reached directly, and everything else refused. List a
  hostname — any port, or `host:port` for one — and it goes through the proxy; list
  an **address** such as `192.168.1.50:5432` and the sandbox reaches it directly,
  which is what a database or any non-HTTP client needs. A port you name is also
  published on this machine's loopback, so you can reach a server the sandbox runs.
  A hostname that resolves into local or private address space stays refused — list
  the address itself to reach it on purpose. `internet` is one click away for work
  that needs the open web, and `none` leaves only the model API reachable.
* **Requests you never see.** Asking for something the sandbox already has — a
  directory inside `/workspace` or inside a directory you already shared, a host
  already on the allowlist, a tool already in the image — is refused automatically,
  with a note saying where it already is. It is a refusal rather than an automatic
  approval, because an approval is yours to give; anything ambiguous still reaches
  you.
* **Turning the questions off.** One checkbox in the Permissions tab stops a project
  being asked anything, and the request dialog has a quiet "Stop asking" button that
  sets it. Off means off: every request already waiting is refused with the reason,
  the sandbox is told not to ask, and a request written straight into its spool is
  refused on arrival rather than shown to you. On is the default.
* **Kernel hardening.** A hardened seccomp profile is **on by default** and
  attached with `--security-opt=seccomp=`. Its 16 rules deny 69 syscalls, among them
  `mount`, `unshare`, `setns`, `pivot_root`, `chroot`, `bpf`, `ptrace`, `keyctl`,
  `pidfd_getfd`, `init_module`, `open_by_handle_at`, `userfaultfd`,
  `perf_event_open`, `io_uring_*`, every `CLONE_NEW*` flag, and the exotic socket
  families (`AF_VSOCK`, `AF_ALG`, `AF_PACKET`, `AF_TIPC`, `AF_XDP`). The image also
  carries the profile's digest, and a sandbox refuses to start unless the profile
  being applied is byte-for-byte the one the image was built with. If the profile
  cannot be found, no plan is built at all rather than a weaker container starting.
* **Permissions.** The sandbox can *write* requests and *read* answers. The
  answer directory is mounted read-only, so a compromised sandbox cannot forge
  an approval or rewrite its own grant list. It can only ask. The request file
  itself is not authenticated — it cannot be, since the bridge is the agent's own
  child process — so the prompt you answer *is* the control, and there is
  deliberately no auto-approve path that could turn a forged request into a silent
  grant. See [docs/SECURITY.md](docs/SECURITY.md#the-request-spool-is-not-authenticated).

Every one of those claims has tests. See [docs/SECURITY.md](docs/SECURITY.md),
which also lists what this does **not** protect against.

## Repository layout

```
Deepsand/
├─ AGENTS.md                 how to work on this repository
├─ crates/deepsand-core/     Rust: path guards, policy, store, broker, proxy, secrets
│  └─ src/bin/deepsandctl.rs headless driver
├─ src-tauri/                Tauri app: the commands, PTY hosting, remote server
├─ src/                      SolidJS UI: terminal, permissions, tools, secrets, activity
├─ runtime/                  The in-container half
│  ├─ Dockerfile
│  ├─ bin/entrypoint.sh      settings, egress rules, privilege drop
│  ├─ bin/netfilter.sh       the network policy
│  ├─ bin/deepsand-mcp-bridge.mjs   the API DeepCode asks through
│  ├─ skills/                Agent Skills installed into the sandbox
│  └─ seccomp-hardened.json  the hardened profile, attached by default
├─ probe/                    escape probes to compile and run inside the sandbox
└─ docs/                     ARCHITECTURE.md, SECURITY.md
```

The GUI contains no policy: that lives in `deepsand-core`, which is why the
desktop app and the headless CLI cannot behave differently.

## Development

```bash
npm run app:dev              # app with hot reload
npm run core:test            # 310 Rust tests: paths, policy, broker, proxy, credentials, seccomp, durability
npm run test:bridge          # 55 checks: the permission protocol end to end
npm test                     # both suites
npm run core:check           # cargo check --workspace
npm run build                # typecheck + bundle the frontend
npm run runtime:icons        # regenerate src-tauri/icons from code
```

### Building an installer locally

`npm run app:build` produces what you would ship, and it is slow on purpose: the release
profile is `lto = true` with `codegen-units = 1`, which makes the final link a
whole-program one. The other three exist because most local builds are not shipping:

| Command | What it does | When it is right |
| --- | --- | --- |
| `npm run app:dev` | dev profile, hot reload, no bundling | iterating on code — seconds, not minutes |
| `npm run app:build:debug` | debug profile, NSIS installer only | you want to *install* your change and click around |
| `npm run app:build:fast` | release profile with **LTO off**, NSIS only, unsigned | you want something close to the real thing, quickly |
| `npm run app:build:binary` | builds the executable, packages nothing | checking that it compiles |
| `npm run app:build` | release, every bundle target, LTO on, signed | making a release |

On Windows the release build makes **two** installers (MSI and NSIS) because
`bundle.targets` is `"all"` so that each platform in the release matrix builds its own.
The `--bundles nsis` in the fast variants skips WiX and the MSI entirely.

`app:build:fast` turns LTO off because that is the only thing that measurably helps.
Swapping the *linker* does not: a release relink after touching one file measures 219 s
with the MSVC linker and 212 s with `rust-lld`, because with `lto = true` the time is LLVM
optimizing across every crate *before* a linker is invoked. Turning LTO off is what takes
the minutes out. It produces a slightly larger, slightly slower binary, which is why the
shipping build keeps `lto = true`.

A release build also needs the updater key in the environment, or it stops with an error
about updater artifacts (see [Install](#install)).

The interesting tests are the ones that assert containment rather than behaviour — `a_plan_never_mounts_a_container_runtime_socket`, `the_reply_channel_can_never_be_written_by_the_sandbox`, `symlinks_are_resolved_before_guards_run`. They are listed in [docs/SECURITY.md](docs/SECURITY.md).

Contributors and coding agents should read [AGENTS.md](AGENTS.md) first: it lists the invariants that are load-bearing, the platform quirks that will otherwise cost you an afternoon, and what counts as done.

## Releases and updates

Pushing to the `release` branch, or running the **release** workflow from the Actions tab, builds installers for Windows, Linux (x86_64 and ARM64) and macOS (Apple Silicon and Intel), signs them, and opens a **draft** GitHub release. Review the artifacts and the notes, then publish the draft — the update manifest (`latest.json`) is only served from a published release, so nothing is offered to installed copies until you do.

The app updates itself. It checks a few seconds after startup and says so if something newer exists; **Settings → Updates** has the current version, a *Check for updates* button, and the install button. Installing restarts Deepsand, which stops any running sandbox, so the dialog says that before you click rather than after.

Two things are worth knowing before the first release:

* **The signing key is a secret, and losing it is permanent.** `npm run tauri signer generate -- -w ~/.tauri/deepsand.key` creates it; the public half goes in `src-tauri/tauri.conf.json` and the private half goes in the repository's `TAURI_SIGNING_PRIVATE_KEY` secret (and, only if you set one, `TAURI_SIGNING_PRIVATE_KEY_PASSWORD`). The workflow refuses to build without it. Whoever holds that key can sign an update that every installed copy will accept, and if it is lost, no already-installed copy can ever be updated again.
* **Bump all three version fields together** — `src-tauri/tauri.conf.json`, `package.json` and the workspace `Cargo.toml`. The tag, the release name and the update manifest all come from them, and the workflow fails early if they disagree, because a mismatch produces a release that tells installed copies they are already up to date.

macOS builds are ad-hoc signed, not notarised: there is no Apple Developer certificate here, so macOS will warn about the first launch of a downloaded copy. Windows builds are unsigned, so SmartScreen will warn too. Neither warning is about the update signature, which is separate and always enforced.

## Credits and licensing

Deepsand is an independent wrapper and is not affiliated with the DeepCode project. It drives the published `@vegamo/deepcode-cli` package from inside a container; the DeepCode source is never vendored into this repository (a checkout under `reference/` is gitignored).

[ESMV licensed](https://github.com/L1lith/ESMV).
