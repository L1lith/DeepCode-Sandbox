# The sandbox runtime

This directory is the **inside** of the sandbox. Everything Deepsand claims about
containment is either enforced by the files here or by the mount list that
`crates/deepsand-core/src/policy.rs` builds against them.

```
runtime/
├─ Dockerfile                    the whole universe the sandbox can see
├─ bin/
│  ├─ entrypoint.sh              settings, egress rules, privilege drop, exec
│  ├─ netfilter.sh               the network policy, installed as root
│  └─ deepsand-mcp-bridge.mjs    the API DeepCode asks permission through
├─ skills/
│  └─ deepsand-permissions/
│     └─ SKILL.md                playbook DeepCode loads when it needs access
├─ seccomp-hardened.json         opt-in additive seccomp profile
└─ scripts/
   ├─ build-image.mjs            docker build with the configured tag
   ├─ test-mcp-bridge.mjs        drives the bridge against a simulated broker
   └─ make-icon.mjs              regenerates the app icon from code
```

## Building

```bash
node runtime/scripts/build-image.mjs                      # uses the tag in Deepsand's state
node runtime/scripts/build-image.mjs deepsand/runtime:dev # or an explicit tag
DEEPSAND_BUILD_ARGS="--build-arg INSTALL_BUILD_TOOLS=1" node runtime/scripts/build-image.mjs
```

`INSTALL_BUILD_TOOLS=1` adds `build-essential`, `python3` and `pkg-config`, which
roughly doubles the image. It is off by default because most projects install
their own toolchains, and a smaller image is a smaller attack surface.

### How the tool plan reaches the build

The app turns a project's tool selection into build arguments, and three of them are
**comma-separated lists**: `APT_PACKAGES`, `NPM_GLOBALS` and `CARGO_INSTALLS`. Commas
rather than spaces because a build argument is a single argv entry and needs no quoting.

The Dockerfile splits them **once**, at the top of the step that uses them, into the same
names. Do it there and not at each use. The apt branch used to expand `$APT_PACKAGES`
directly, so apt was handed the whole list as one package name:

```
E: Unable to locate package curl,git,jq,ripgrep,unzip,zip
```

Every project whose tools needed an apt package failed to build an image, in four
seconds, with an error that named none of this. `crates/deepsand-core/tests/runtime_dockerfile.rs`
now asserts the split happens before every use, so a new list-valued argument that
forgets to be split fails a unit test instead of a build. The same file is why a failed
build now reports the last lines of its own output.

## The container's startup sequence

`entrypoint.sh` runs as root for exactly three reasons, in this order:

1. **Materialise the settings.** `/etc/deepsand/settings.json` (mounted `:ro` from
   Deepsand's private data directory) is copied to
   `$HOME/.deepcode/settings.json`. Copying rather than mounting directly means
   the sandbox cannot write back to a host-owned file, and the home volume
   always ends up with a usable one. `/etc/deepsand/AGENTS.md` is handled the
   same way.
2. **Install the egress policy.** `netfilter.sh` runs in the container's own
   network namespace. This is *fail-closed*: if the rules cannot be installed the
   container exits rather than running with an open network, unless
   `DEEPSAND_NETFILTER_OPTIONAL=1` was set explicitly.
3. **Adopt the state volume.** A freshly created named volume is root-owned, so
   ownership is fixed before the drop.

Then it drops everything with

```
setpriv --reuid=1000 --regid=1000 --clear-groups \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs
```

and `exec`s DeepCode. After that point nothing in the container can run
`iptables`, regain a capability, or become root.

## The MCP bridge

`deepsand-mcp-bridge.mjs` is a stdio MCP server that DeepCode spawns because
Deepsand puts it in the generated `settings.json` under `mcpServers`. It is
deliberately powerless:

* it can **write** request files into `/deepsand/ipc/requests`
* it can **read** replies from `/deepsand/ipc/responses`
* it can **read** its own description from `/deepsand/state`

The last two are mounted read-only, which is the entire security model of the
permission system in one mount flag: the sandbox can ask, but it cannot answer.

It exposes four tools:

| Tool | Purpose |
| --- | --- |
| `deepsand_sandbox_info` | What can I currently reach? Also the network policy and why. |
| `deepsand_request_directory_access` | "I need `C:\Users\me\brand`" — the operator sees the exact path. |
| `deepsand_request_resource` | "I need the my-website repo but can't see where it is" — the operator gets a folder picker. |
| `deepsand_check_request` | Collect the answer to a request that came back as `PENDING`. |

Because DeepCode caps MCP `tools/call` at 60 s, the bridge waits ~45 s and then
answers `PENDING` with a request id rather than failing the call.

## Agent Skills

The sandbox ships one Agent Skill, `deepsand-permissions`, installed at
`/home/deepcode/.agents/skills/deepsand-permissions/SKILL.md` by the Dockerfile.
It is the detailed playbook for asking for access: which of the two request tools
to use, how to read an approval reply, and how to handle `PENDING`.

**Why a skill and not just `AGENTS.md`.** DeepCode teaches the sandbox about its
permissions through three channels, and they are not equally reliable:

| Channel | Reach |
| --- | --- |
| MCP tool descriptions | Always present — the tools are in the model's tool list every turn. This is why the model always knows the request tools exist. |
| `AGENTS.md` | **Conditional.** DeepCode loads `<project>/AGENTS.md` or `<project>/.deepcode/AGENTS.md` if either exists, and only falls back to `~/.deepcode/AGENTS.md` when the project has neither. Most real repositories ship their own `AGENTS.md`, so the user-level file is silently ignored in exactly the projects that need it most. |
| Agent Skills | Discovered from four roots independently of `AGENTS.md`, and selected by the model from each skill's name and description. |

So the tool descriptions carry the essentials and the skill carries the depth. The
generated `AGENTS.md` cross-references the skill, but nothing depends on that file
being loaded.

### Where DeepCode looks for skills

Scanned in this order, deduplicated by name, first match wins:

```
<project>/.deepcode/skills/<name>/SKILL.md    project, native
<project>/.agents/skills/<name>/SKILL.md      project, interoperable
~/.deepcode/skills/<name>/SKILL.md            user, native
~/.agents/skills/<name>/SKILL.md              user, interoperable
bundled:<name>/SKILL.md                       shipped inside the CLI package
```

Plus `enabledSkills` in settings, which can disable a skill by name.

Deepsand installs at **user level** so nothing is ever written into the operator's
repository. A skill is only picked up if it is a directory containing a readable
`SKILL.md` whose frontmatter has a `name` and a `description`, which is why the
Dockerfile asserts both and fails the build otherwise. Adding
`metadata: { allow-implicit-invocation: false }` to the frontmatter would hide a
skill from automatic selection and require an explicit slash command instead.

### Verifying it

DeepCode's own resolver scans the same roots, so it can be used as the authority.
Note that the bundled `find-skill.js` in `skill-digester` is written as CommonJS
inside a `"type": "module"` package, so running it directly fails; copy it to a
`.cjs` name first:

```bash
docker run --rm --entrypoint sh deepsand/runtime:0.1.0 -c '
  FS=/usr/local/lib/node_modules/@vegamo/deepcode-cli/bundled/skill-digester/scripts/find-skill.js
  cp "$FS" /tmp/find-skill.cjs
  node /tmp/find-skill.cjs deepsand-permissions /workspace'
```

It resolves to `~/.agents/skills/deepsand-permissions/SKILL.md`, scope `user`.

### Testing the bridge

The bridge only talks to the host through those three directories, so the host
broker can be simulated exactly:

```bash
node runtime/scripts/test-mcp-bridge.mjs
```

40 checks covering the handshake, both prompts, approval and denial rendering,
the pending path, hostile input, and a bridge whose spool has gone missing.
