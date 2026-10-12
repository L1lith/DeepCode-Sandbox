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
│  ▸ api-server        │  [Terminal] [Permissions 2] [Activity]           │
│                      │                                                  │
│  [+ New project]     │   Deep Code  v0.4.3                              │
│                      │   > add a dark mode toggle to the header         │
│                      │                                                  │
│                      │   ● DeepCode is trying to access                 │
│                      │     C:\Users\me\Documents\brand                  │
│                      │     [Deny]  [Grant access]                       │
└────────────────────────────────────────────────────────────────────────┘
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

## Install

Requires **Docker Desktop** (or Docker Engine on Linux) and, to build from
source, **Node.js ≥ 22** and **Rust ≥ 1.82**.

```bash
git clone https://github.com/L1lith/DeepCode-Sandbox
cd DeepCode-Sandbox
npm install

npm run runtime:build     # build the sandbox image (once, ~3 min)
npm run app:build         # produce the installer for your platform
```

For development, `npm run app:dev` starts the app with hot reload.

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
* **Network.** Default is *anything that is not on your local network*: public
  internet works, your host, your LAN, link-local and cloud metadata
  (`169.254.169.254`) are rejected by the container's own kernel. Switch a
  project to `restricted` for a hostname allowlist through a filtering proxy, or
  `none` for no network at all.
* **Permissions.** The sandbox can *write* requests and *read* answers. The
  answer directory is mounted read-only, so a compromised sandbox cannot forge
  an approval or rewrite its own grant list. It can only ask.

Every one of those claims has tests. See [docs/SECURITY.md](docs/SECURITY.md),
which also lists what this does **not** protect against.

## Repository layout

```
DeepCode-Sandbox/
├─ crates/deepsand-core/     Rust: path guards, policy, store, broker, proxy, PTY
│  └─ src/bin/deepsandctl.rs headless driver
├─ src-tauri/                Tauri app: 30 commands over the core, PTY hosting
├─ src/                      SolidJS UI: terminal, permission dialogs, settings
├─ runtime/                  The in-container half
│  ├─ Dockerfile
│  ├─ bin/entrypoint.sh      settings, egress rules, privilege drop
│  ├─ bin/netfilter.sh       the network policy
│  ├─ bin/deepsand-mcp-bridge.mjs   the API DeepCode asks through
│  └─ seccomp-hardened.json  opt-in additive profile
└─ docs/                     ARCHITECTURE.md, SECURITY.md
```

The GUI contains no policy: that lives in `deepsand-core`, which is why the
desktop app and the headless CLI cannot behave differently.

## Development

```bash
npm run app:dev              # app with hot reload
npm run core:test            # 84 Rust tests: paths, policy, broker, proxy, PTY
npm run test:bridge          # 40 checks: the permission protocol end to end
npm run build                # typecheck + bundle the frontend
npm run runtime:icons        # regenerate src-tauri/icons from code
```

The interesting tests are the ones that assert containment rather than behaviour — `a_plan_never_mounts_a_container_runtime_socket`, `the_reply_channel_can_never_be_written_by_the_sandbox` `symlinks_are_resolved_before_guards_run`. They are listed in [docs/SECURITY.md](docs/SECURITY.md).

## Credits and licensing

Deepsand is an independent wrapper and is not affiliated with the DeepCode project. It drives the published `@vegamo/deepcode-cli` package from inside a container; the DeepCode source is never vendored into this repository (a checkout under `reference/` is gitignored).

[ESMV licensed](https://github.com/L1lith/ESMV).
