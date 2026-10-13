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
| `npm run core:test` | `cargo test -p deepsand-core` — 296 tests |
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
13. **`reference/` is never committed, vendored or bundled.** Upstream DeepCode CLI
    source is downloaded there read-only, and gitignored.
14. **The update signing key never enters the repository, and its loss is
    permanent.** The private half lives in `~/.tauri/deepsand.key` and in the
    `TAURI_SIGNING_PRIVATE_KEY` secret; the public half is pinned in
    `src-tauri/tauri.conf.json`, which is what every installed copy verifies
    against. Whoever holds the private key can sign an update that all of them
    will install, and losing it means no installed copy can ever be updated.
    `.gitignore` covers `*.key` as a backstop, not as permission to be careless.
15. **The three version fields move together** — `src-tauri/tauri.conf.json`,
    `package.json`, and `version` in the workspace `Cargo.toml`. The release
    workflow fails early when they disagree, because a release whose manifest
    version is wrong tells every installed copy it is already up to date: a
    silent failure where nobody gets an error and nobody gets the update.
16. **The updater is reachable only through our own two commands.** The plugin is
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
* **Moving or renaming the checkout needs `cargo clean`.** Two things bake the
  absolute path of the working directory into build output: `env!("CARGO_MANIFEST_DIR")`
  in the test that reads `runtime/seccomp-hardened.json`, and Tauri's generated
  permission files under `target/debug/build/tauri-*/out/`. After a rename the stale
  binary or build script looks in the old directory and fails with `os error 3` and a
  path you no longer have. `cargo clean -p tauri -p tauri-build` covers the second;
  touching the file covers the first.

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
