# Architecture

Deepsand runs [DeepCode](https://github.com/lessweb/deepcode-cli) inside a Docker
container and makes it impossible for that container to reach anything the
operator did not explicitly share.

Three processes are involved, and it is worth being precise about which one is
allowed to decide what.

```
┌──────────────────────────────────────────────────────────────────────────────┐
│ HOST                                                                         │
│                                                                              │
│   ┌───────────────────────────┐        ┌──────────────────────────────────┐  │
│   │ Deepsand desktop (Tauri)  │        │ deepsandctl (headless)           │  │
│   │  SolidJS UI  ──IPC── Rust │        │  same core, no display           │  │
│   └─────────────┬─────────────┘        └────────────────┬─────────────────┘  │
│                 │                                       │                    │
│                 └──────────────┬────────────────────────┘                    │
│                                ▼                                             │
│                    ┌───────────────────────┐                                 │
│                    │ deepsand-core (Rust)  │  ← the only place policy lives  │
│                    │  paths / policy       │                                 │
│                    │  store / broker       │                                 │
│                    │  proxy / session      │                                 │
│                    └───────┬───────────────┘                                 │
│                            │ docker run (one argv, no shell)                 │
│        ┌───────────────────┴────────────────────┐                            │
│        │ bind mounts            │ spool dirs     │ named volume               │
│        ▼                        ▼                ▼                            │
│  ┌───────────────────────────────────────────────────────────────┐           │
│  │ SANDBOX CONTAINER                                             │           │
│  │  entrypoint.sh  → settings, egress rules, setpriv drop        │           │
│  │  deepcode (uid 1000, no capabilities)                         │           │
│  │    └─ MCP server: deepsand-mcp-bridge.mjs                     │           │
│  └───────────────────────────────────────────────────────────────┘           │
└──────────────────────────────────────────────────────────────────────────────┘
```

## Where the rules live

| Concern | Enforced by | Notes |
| --- | --- | --- |
| Which host paths may ever be mounted | `crates/deepsand-core/src/paths.rs` | Symlinks resolved first, then a denylist of system, credential and Deepsand-own directories. |
| What the container is allowed to be | `crates/deepsand-core/src/policy.rs` | Emits the one and only `docker run` argv. Refuses to build a weakened one. |
| Privilege and filesystem hardening at runtime | `runtime/bin/entrypoint.sh` | Materialises settings, drops every capability and the bounding set, `exec`s as uid 1000. |
| Network policy | `runtime/bin/netfilter.sh` | Kernel rules inside the container's own net namespace, installed before the drop. |
| The permission protocol | `runtime/bin/deepsand-mcp-bridge.mjs` + `crates/deepsand-core/src/broker.rs` | The sandbox can *ask*; only the host can *answer*. |
| Allowlist egress | `crates/deepsand-core/src/proxy.rs` | Hostname allowlist, host-side DNS, private-address refusal. |

The GUI contains no policy. That is deliberate: it means the desktop app and the
headless CLI cannot drift apart, and a reviewer can read the whole boundary in
four files.

## Starting a sandbox

1. **Validate.** The workspace and every grant are canonicalised (symlinks
   resolved) and run through the path guards. This happens again at plan time,
   not only when the user clicks, so a grant recorded before a policy change can
   never be honoured afterwards.
2. **Generate.** `deepsand-core::settings` writes three files into Deepsand's
   private data directory (never the user's project):
   - `config/settings.json` — the DeepCode configuration, including the MCP
     server entry and the merged credential resolution.
   - `config/AGENTS.md` — standing instructions that tell the contained model how
     its sandbox behaves and how to ask for more.
   - `state/sandbox.json` + `state/grants.json` — what the sandbox is allowed to
     know about itself.
3. **Plan.** `policy::plan_run` produces the argv. If anything is unsafe it
   returns an error instead of a plan.
4. **Run.** `docker run` is spawned under a real PTY (ConPTY on Windows), and the
   PTY is what the terminal pane renders. The host broker thread starts watching
   the request spool.

## The permission protocol

Two directories, and the difference between them is the entire security model:

| Host | Container | Mode |
| --- | --- | --- |
| `<data>/projects/<id>/ipc/requests` | `/deepsand/ipc/requests` | **read-write** |
| `<data>/projects/<id>/ipc/responses` | `/deepsand/ipc/responses` | **read-only** |
| `<data>/projects/<id>/state` | `/deepsand/state` | **read-only** |

The sandbox can write a request. It cannot write an answer, because the answer
directory is mounted read-only. It can only ever ask.

A request is produced by `runtime/bin/deepsand-mcp-bridge.mjs`, which DeepCode
spawns as an MCP server. The bridge publishes `<id>.json` atomically and polls
for a reply.

```
model                bridge               spool                Deepsand             operator
  │                    │                    │                      │                   │
  ├─ mcp__deepsand__ ─▶│                    │                      │                   │
  │  request_directory │                    │                      │                   │
  │  _access           ├─ write req.json ──▶│                      │                   │
  │                    │                    ├─ poll (400 ms) ─────▶│                   │
  │                    │                    │                      ├─ dialog ─────────▶│
  │                    │                    │                      │◀─ allow/deny ─────┤
  │                    │◀─ read resp.json ──┤◀─ write resp.json ───┤                   │
  │◀─ "APPROVED, at    │                    │                      │                   │
  │    /grants/brand" ─┤                    │                      │                   │
```

Two details follow from how DeepCode is built:

* **MCP `tools/call` is capped at 60 s** (`MCP_CALL_TOOL_TIMEOUT_MS` in
  `packages/core/src/mcp/mcp-manager.ts`). The bridge therefore waits ~45 s and,
  if the operator has not answered, replies `PENDING` with a request id and the
  model collects the answer later with `deepsand_check_request`.
* **Bind mounts cannot be added to a live container.** So an approval recreates
  the container. Session state lives in a named volume at
  `/home/deepcode/.deepcode`, and DeepCode's `--last` flag resumes the previous
  session for that project. `--last` calls `process.exit(1)` when there is no
  session, so Deepsand *verifies* the session index exists in the volume before
  using it.

## The two prompts

The bridge exposes four tools; two of them map exactly onto the product's two
prompts.

| Tool | Dialog |
| --- | --- |
| `deepsand_request_directory_access` | **"DeepCode is trying to access C:\\Users\\me\\Documents\\brand"** — the sandbox named a path, so the dialog shows that exact path. |
| `deepsand_request_resource` | **"DeepCode is requesting access to the my-website repo"** — the sandbox knows *what* but not *where*, so the operator gets a folder picker. It is told only where the result appears inside itself, never the host path. |
| `deepsand_sandbox_info` | Not a prompt: lets the model see what it can currently reach instead of guessing or hunting. |
| `deepsand_check_request` | Not a prompt: collects a late answer. |

A path named in a request is only ever used to *prefill* a dialog. Whatever the
operator approves is validated from scratch on the host.

## Network policy

| Mode | Container flags | Effect |
| --- | --- | --- |
| `internet` (default) | `--cap-add=NET_ADMIN` | Public internet reachable. RFC1918, loopback, link-local, CGNAT, multicast and reserved ranges rejected at the kernel, except DNS to the configured resolvers. |
| `none` | normal bridge + in-container rules limited to the proxy | Only the model API is reachable. `--network=none` was dropped deliberately: with no interfaces the sandbox could not reach the proxy on the host, so it could not reach its own model API and the mode was unusable. |
| `restricted` | project bridge network + `DEEPSAND_PROXY_ADDR` | Only the Deepsand allowlist proxy is reachable. The proxy resolves names itself and refuses anything landing in private address space. |
| `full` | neither | No restriction, including the host's own services. |

The default exists because "the local network" is exactly where the interesting
things are: the host's own services, the router's admin page, and cloud metadata
at `169.254.169.254`.

## Why filesystem isolation is the strong guarantee

Everything above is policy, and policy can be argued with. The filesystem
containment is not policy: inside the container, the host's filesystem *does not
exist*. There is no path, no symlink and no mount that reaches it, because
Docker never gave the container a reference to it.

The concrete consequences:

* A symlink inside a shared directory pointing at `../../..` resolves inside the
  container's own mount namespace. There is nothing there.
* A path traversal in a file read escapes a mount only if a mount exists to
  escape to. There is no mount onto the host.
* The docker socket is not mounted, so the sandbox cannot ask the daemon for a
  new container with different flags. `policy.rs` additionally refuses to build a
  plan containing anything socket-shaped, as a defence against a future bug.
* The `:ro` on the response spool means the sandbox cannot forge an approval even
  though it can write files next to it.

See [SECURITY.md](SECURITY.md) for the escape analysis and the known limits.
