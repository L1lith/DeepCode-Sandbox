---
name: deepsand-permissions
description: Ask the operator for access to files, directories, network destinations, tools or other resources that are outside this Deepsand sandbox, and interpret the answer. Use when a needed path is not under /workspace or /grants, when a file or directory seems to be missing, when you need something whose location on the operator's machine you do not know, when a command fails because of the network policy (an unreachable host, a blocked npm install or git clone), when you need a tool that is not installed, or before concluding that something is unavailable and giving up.
---

# Requesting access in a Deepsand sandbox

You are running inside a Docker container that Deepsand created. It has no reference to the operator's filesystem beyond the directories that were mounted into it. Anything you cannot reach is not hidden from you — it is genuinely absent from your mount namespace. There is no traversal, symlink or flag that reaches it.

This means "not found" almost never means "broken". It usually means "not shared yet", and there is a supported way to ask.

## Decide which request to make

Four tools cover every case. Choosing correctly matters, because the operator sees a different prompt for each, and asking with the wrong one means the question they are shown does not match what you actually need.

**`deepsand_request_resource`** — use this when you know *what* you need but not *where* it lives on the operator's machine. You cannot see their disk, so you generally cannot know a host path. Examples:

- "the my-website repository"
- "the brand assets folder"
- "the .env file for this service"

The operator gets a folder picker and locates it for you. You never learn the host path; you are told where it appears inside the sandbox.

**`deepsand_request_directory_access`** — use this only when the operator has already told you a host path, or when a previous reply gave you one. You are asserting a location, so naming one you guessed will simply be refused. Examples:

- the operator said "the assets are in `D:\design\brand`"
- a previous approval reply mentioned a host path

Do not guess at host paths. A guessed path wastes the operator's attention and comes back denied.

**`deepsand_request_network_access`** — use this when a command failed because a destination is blocked: an unreachable host, a package install that cannot reach its registry, a `git clone` that hangs. Include the blocked command verbatim and ask for the narrowest pattern that will work. See the network section below.

**`deepsand_request_tool`** — use this when you need a program that is not installed. You cannot install it yourself in a way that survives, so ask. See the toolbox skill for what is available.

## Before you ask

Call **`deepsand_sandbox_info`** first. It lists the workspace, every granted directory, and the network policy in plain language. Its output is the current truth. Asking for something you already have, or for a directory that is already mounted under a different name, is the most common way to annoy the operator.

## Asking, and what comes back

A request returns one of three things:

- **`APPROVED`** — the directory is now mounted and the reply tells you the path
  it appears at, under `/grants/<name>`. **Use the path from the reply, not one you predicted.** The name is chosen by the operator's Deepsand instance, so it may not match what you asked for.
- **`DENIED`** — the decision is final. Do not retry it, do not rephrase it, do not look for another route to the same place. Report the limitation and continue with what you have, or ask the operator what they would prefer.
- **`PENDING`** — nobody has answered yet. The reply includes a `request_id`.

## The `PENDING` case

DeepCode caps a tool call at 60 seconds, and a human may take longer than that. A `PENDING` result is normal and is **not** a failure:

1. Do not file a second request for the same thing. That queues a duplicate and the operator has to dismiss it.
2. Continue with any work that does not depend on the answer.
3. Call **`deepsand_check_request`** with the `request_id` to collect it.

Poll no more than a few times, and keep doing useful work in between. When the operator approves, Deepsand recreates your container to attach the new mount and resumes this session, so your conversation is not lost — but your working directory listing may briefly change underneath you.

## The network

`deepsand_sandbox_info` reports the mode and, in allowlisted mode, exactly which destinations are reachable. If a host is unreachable and the mode is not `full`, that is the policy working, not a transient fault. Do not retry with a different tool, and do not reach for a proxy: there is no alternate route, and trying one wastes the turn.

Ask with **`deepsand_request_network_access`**. Give it:

- `patterns` — the destinations, narrowest first
- `command` — the exact command that was blocked. This is the most useful thing you can include, because it is what lets the operator judge whether the request is reasonable
- `purpose` — one sentence

### Patterns

| Pattern | Matches |
|---|---|
| `registry.npmjs.org` | that host exactly, on any port |
| `registry.npmjs.org:8443` | that host, on that port only |
| `*.example.com` | its **subdomains**, but not `example.com` itself |
| `github.com/org/repo` | only paths under that prefix — and only over plain HTTP, because an HTTPS CONNECT tunnel carries no path |
| `192.168.1.50:5432` | that address, on that port — for a database, or anything that is not HTTP |
| `192.168.1.50` | that address, on any port |
| `!tracker.example.com` | denies; a deny always beats an allow |

An entry with no port covers **every** port on that destination, so name the port when
you know it: it is a narrower rule and a more persuasive request.

A blanket `*` is refused before the operator ever sees it. Never ask for one.

### Addresses, and the refusal that is not an accident

If the blocked destination is an **IP address**, ask for the address — `["192.168.1.50:5432"]`
rather than `["db.internal"]`. An address entry is also what a client that speaks no
HTTP needs, because the sandbox reaches a named address directly instead of through
the proxy.

A request for a **hostname** that resolves into local or private address space is
refused even when the hostname is allowed. That is deliberate: a name can be made to
resolve somewhere else later, so a name is never evidence of which machine is meant.
The refusal message names the address to ask for instead. Read it, and ask for that
address rather than the name again.

### If you are told you already have it

Some requests are answered without the operator ever seeing them, because the sandbox
already has what you asked for: a directory inside `/workspace` or inside an
already-shared directory, a host that is already on the allowlist, or a tool that is
already installed. The answer names where it already lives, such as `/workspace/src`
or `/grants/brand-assets/logos`. Use that directly — it is not a refusal, and asking
again gets the same answer. `deepsand_sandbox_info` lists all of it up front, which is
why checking it first is worth the call.

### Good and bad requests

**Good** — blocked by the allowlist, cause understood, narrow:

```
patterns: ["registry.npmjs.org"]
command:  "npm install react"
purpose:  "installing the project's dependencies"
```

**Good** — several hosts that are genuinely needed together, asked once:

```
patterns: ["pypi.org", "files.pythonhosted.org"]
command:  "pip install -r requirements.txt"
purpose:  "installing the project's Python dependencies"
```

**Bad** — a blanket allow. Refused automatically, and it is not a request a person should have to refuse:

```
patterns: ["*"]
```

**Bad** — inventing a hostname. If you are not sure of the destination, read the error message: it names the host that was refused.

```
patterns: ["npmjs.org"]        # wrong; the messages came from registry.npmjs.org
```

**Bad** — asking for a pattern much wider than the failure:

```
patterns: ["*.com"]            # for one blocked request to a single registry
```

### If you are denied

The refusal may come with a reason. You get **one** further attempt, and only with a *narrower* pattern — never the same one rephrased. If the narrower request is also denied, stop asking, report what you could not reach, and continue with the rest of the work.

## Tools

If a program you need is not on `PATH`, do not try to install it yourself: an install inside the running container is lost when the sandbox is recreated, and for a package manager it may not even be the same thing the project would use.

Call **`deepsand_sandbox_info`** to see which tools are already present, then **`deepsand_request_tool`** with the ids you need. Ask for several at once if you know you need them together.

An approved tool is added to the project's image, which means it is **not usable yet**. The reply says so. Do not retry the original command expecting it to work; report that the tool has been approved and needs the image rebuilt, and continue with what you can do.

## What not to do

- Do not search the filesystem for a way around a missing path. There is not one, and the attempt is wasted work.
- Do not assume a standard layout (`~/.ssh`, `/etc`, the operator's home) exists. Those are deliberately absent.
- Do not silently work around a missing input by inventing its contents. Say what is missing and ask.
- Do not retry a denied request. A refusal is a decision, and there is no workaround.
- Do not ask for a wildcard to avoid diagnosing which host you actually need. The error message usually says.
- Do not install tools yourself. They are baked into the image; an install you perform is discarded, and installing something else with a different version is worse than not having it.
- Do not bundle unrelated requests into one to save a round trip. A request the operator cannot judge is a request they have to refuse.
