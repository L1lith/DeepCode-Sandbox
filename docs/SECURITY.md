# Security model

Deepsand's promise is narrow and testable: **the sandbox can only reach the
project directory plus the directories the operator explicitly granted.**

This document states how that is enforced, what it does *not* protect against,
and where the honest gaps are. It is written to be argued with.

## The boundary, in one sentence

The container has no reference to the host filesystem other than the bind mounts
`policy.rs` chose, so there is nothing to escape *to*: the host's files do not
exist inside the container's mount namespace.

Everything else below is defence in depth on top of that.

## Enforced properties

### Filesystem

| Property | Enforced by |
| --- | --- |
| Only the workspace and grants are mounted | `policy.rs` builds the complete mount list; `audit_mounts` rejects anything outside it |
| The reply spool and sandbox state are read-only | `MountKind::must_be_read_only`, asserted in `audit_mounts` and covered by tests |
| No container-runtime socket | `audit_mounts` rejects any source containing `docker.sock`, `docker_engine`, `containerd.sock`, `podman.sock` or a `//./pipe/docker` path |
| The container root filesystem is read-only | `--read-only`, with `/tmp` and `/run` as sized tmpfs |
| Mount targets cannot shadow `/`, `/proc` or `/sys` | `audit_mounts` |
| Grants cannot nest or contain the workspace | `store::add_grant` rejects overlaps, in both directions |
| Two mounts cannot share a target | `audit_mounts` |

### Path validation (`paths.rs`)

Guards run twice: when a grant is created and again when the plan is built. A
grant that became forbidden after it was recorded is skipped with a warning
rather than mounted.

Refused, always, whatever the operator clicks:

* filesystem roots (`/`, `C:\`)
* the home directory itself, and any ancestor of it
* Deepsand's own data directory, anything inside it, and any ancestor of it
* the DeepCode config directory (`~/.deepcode`), `.deepcode-plus`
* credential stores: `.ssh`, `.aws`, `.azure`, `.gnupg`, `.kube`, `.docker`,
  `.config/gcloud`, `.config/gh`, `.password-store`, `.terraform.d`
* system trees: on Windows `%windir%`, `Program Files`, `Program Files (x86)`,
  `ProgramData`, `%APPDATA%`, `%LOCALAPPDATA%`; on Unix `/etc`, `/usr`, `/bin`,
  `/sbin`, `/lib*`, `/boot`, `/dev`, `/proc`, `/sys`, `/run`, `/var`, `/root`,
  `/tmp`, `/System`, `/Library`
* UNC paths (`\\server\share`) and Windows device paths (`\\?\`)
* paths containing NUL, and (on non-Windows) `:`, which `-v` cannot express
  unambiguously

**Symlinks are resolved before the guards run**, so a link named `innocent` that
points at `~/.ssh` is judged by its target. There is a test for exactly this.

### Privilege

Started as root only long enough for the entrypoint to do three things, then
every capability, the bounding set and uid 0 are dropped with
`setpriv --bounding-set=-all`:

1. copy the generated settings into the container's own home volume
2. install the egress rules
3. take ownership of the freshly created state volume

The capabilities granted are `CHOWN`, `SETUID`, `SETGID`, and `NET_ADMIN` only
when the network policy needs kernel rules. `--security-opt=no-new-privileges`
means nothing can regain privilege via a setuid binary. DeepCode runs as uid 1000
with an empty capability set.

### Dropping `CAP_DAC_OVERRIDE` has consequences worth knowing

Because the capability set is explicit rather than "everything root gets", the
startup phase runs with `CapEff` = `0xc1` — `CHOWN`, `SETGID`, `SETUID` and
nothing else. Notably `CAP_DAC_OVERRIDE` is **absent**, so root inside this
container is still bound by file permission bits. That is the intended posture,
but it makes the sequencing in `entrypoint.sh` load-bearing:

* `chown` a directory to the sandbox user *and then* write into it as root fails
  with `EACCES`, because the directory is now owned by uid 1000 and root is
  "other". This was a real bug: it surfaced as "could not write
  `/home/deepcode/.deepcode/settings.json`" and left the sandbox with no
  credentials at all.
* The entrypoint therefore creates the directory, takes ownership of it as root,
  copies the credentials in, and only then hands ownership to the sandbox user.

Two further platform quirks are handled the same way. Docker Desktop's volume
driver refuses `chmod` on a volume mount root ("Operation not permitted") even as
root holding `CAP_CHOWN`, so modes there may stay as the mount left them. And the
image's own `/home/deepcode` sits on a read-only rootfs, where any `chown -R`
fails by design. Because none of those operations can be relied upon, the
entrypoint never treats one as authoritative: it performs the ones that work,
tolerates the ones that cannot, and then **verifies the property that actually
matters** — that uid 1000 can read its credentials and write its session volume —
stopping with an explanation if not.

### Network

`internet` mode installs rules **inside the container's own network namespace**,
before the privilege drop, so the sandbox cannot remove them afterwards — it has
no capability to run `iptables`. Blocked: `0.0.0.0/8`, `10/8`, `100.64/10`,
`127/8`, `169.254/16`, `172.16/12`, `192.0.0/24`, `192.168/16`, `198.18/15`,
`224/4`, `240/4`, broadcast. DNS to the container's configured resolvers is
exempted, because without it nothing works. IPv6 is denied outright in
`allowlisted` mode.

`allowlisted` mode — stored as `allowlisted`, still read as `restricted` from an
older state file — allows DNS, the model endpoint, whatever the allowlist names,
and the Deepsand proxy on the project's own bridge gateway. Nothing else. The
allowlist has two enforcement paths, and which one an entry uses is the entry's
own shape:

* **A hostname entry goes through the proxy.** The proxy matches it against the
  allowlist (exact, `*.suffix`, `re:^…$`, `host/path`), **resolves the name
  itself**, and refuses any result in loopback, private, link-local, CGNAT or
  reserved space.
* **An address entry is allowed directly by the container's own rules**, with the
  port it names or every port if it names none, because a database driver or an
  SSH client cannot speak HTTP to a proxy. These are also the entries whose named
  ports are published on the host's **loopback**, so a server the sandbox runs can
  be reached from the operator's side and not from the LAN.

The proxy's private-address refusal is the point of the first path, and an address
entry is the deliberate exception to it. An allowlisted *hostname* that resolves to
`192.168.1.1` — whether by DNS rebinding, a hostile DNS server, or a `hosts` entry —
is refused, so a name can never become a route onto the local network. Naming the
address instead is an explicit instruction to reach that address, and it is the only
way to express "the database on my LAN"; the refusal message says so and names the
address to allow. Ports are part of the decision in both paths: an entry that names
one allows that port only, and an entry that names none allows every port — which is
a widening from the earlier "80 and 443 only" rule, and the reason the UI text no
longer claims otherwise.

A request for a destination that is already reachable is refused without troubling
the operator, with a message that says where the thing already is. That is a `deny`,
never an automatic `allow`: an auto-approval would be consent the operator never
gave, and the bar for skipping them is that there is nothing left to decide. See
`crates/deepsand-core/src/covered.rs`.

`netfilter_required` is on by default, which makes `entrypoint.sh` **fail closed**:
if the egress rules cannot be installed the container exits rather than running
with an open network.

### The permission channel

The sandbox writes requests and reads answers. The answer directory is mounted
`:ro`, so a compromised sandbox cannot:

* forge an approval
* rewrite its own grant list
* edit the settings or the sandbox snapshot it was given

It can only ask. Every decision is made by the host.

Everything arriving on the request spool is treated as hostile input
(`broker.rs`):

* file names must match `req_[a-z0-9_]{1,80}\.json`; anything else is ignored
* the declared `id` must equal the file name
* requests larger than 64 KiB are rejected
* a claimed `host_path` that is actually a container path is dropped, so the
  dialog cannot be prefilled with something the operator would misread
* payload fields are length-capped by character count (not bytes, which could
  split a character) and invalid enum values are removed rather than coerced
* at most 25 requests are surfaced at once, so a flood cannot bury the operator
* answering requires a well-formed id, so a crafted id cannot write outside the
  spool

### The request spool is not authenticated

Round 3 of the escape assessment hand-wrote three request files without calling the
MCP tool at all, and the host processed all three: a correct token with a bogus pid,
a correct token with the real pid, and a *wrong* token. Nothing checked any of it.
That was correct about the behaviour and wrong about the design intent, so this is
the honest version.

**It cannot be fixed by authenticating the file, and the attempt should not be made.**
The bridge is spawned by the sandboxed DeepCode as uid 1000, which is the same uid the
agent runs as: the bridge is not a separate principal, it is the agent's own child.
Any value the bridge can read — an environment variable, a file, a kernel keyring
entry — the agent can read too, so a nonce it can echo into a request is a nonce the
agent can forge. Isolating the bridge in its own mount namespace would need
`unshare`/`setns`, which this profile deliberately denies. The channel is therefore
unauthenticated *by construction*, and the control is the one the design already
relies on: **a human reads the request and decides**. Nothing is granted without that
decision.

What follows from that, and what was changed:

* The session token is **gone** — from the settings, from the container environment
  and from the request. It authenticated nothing, and a field shaped like a credential
  is worse than no field, because it invites the reader to assume a check exists.
  Nothing should be added back in its place unless it is a principal the agent cannot
  impersonate, which needs a second uid, not another string.
* There is **no auto-approve path**, and there must not be one. A rule like "already
  covered by an existing grant" or "the operator approved this path before" would turn
  dialog spoofing into a silent host-directory grant, because the spool cannot tell a
  request the bridge wrote from one the agent wrote. `broker.rs` records every request
  and answers only on an explicit decision; a test asserts that a request is never
  answered without one.
* The pid in a request is a **hint for the operator, not provenance**. It is not
  verified, because the agent can read the real pid from `ps` and copy it, so
  verifying it would add a check that cannot fail in the case that matters.
* The flood caps stay: at most 25 requests are surfaced at once, and the request
  filename, id and size are validated before a dialog exists.
* The operator can **turn asking off** for a project, and that is enforced here on the
  host rather than only in the bridge: an incoming request is answered with a refusal and
  the sandbox is told why, so nothing appears on screen. The bridge checks the same flag
  first and declines to submit, which is a courtesy to the model — it saves it waiting out
  its tool budget — and it is explicitly *not* the control, for the reason above: anything
  in that sandbox can write a request file itself. Turned off, every request already
  waiting is refused too, so the setting is "stop asking" rather than "stop showing me".

## What this does *not* protect against

Being explicit here is more useful than a longer list of things it does.

1. **The operator approving something they should not.** The guards stop the
   worst cases, but granting read-write access to a directory full of secrets is
   a decision only the operator can get right. The dialog names the exact path,
   defaults to read-only, and never inherits a write request.

2. **Model API exfiltration in the default network mode.** In `internet` mode the
   sandbox can reach the public internet, so anything it can read, it can send
   to a remote host. This is inherent to using a hosted model. Use `allowlisted`
   mode with a short allowlist to close it.

3. **`internet` mode does not filter by domain.** It blocks *address ranges*. A
   public pastebin is reachable. `allowlisted` mode is the answer.

4. **Leaked credentials via the project directory.** The API key is injected into
   the container's own home volume, not the project, but a careless setup could
   still put a secret in the workspace: the sandbox can read everything in
   `/workspace`, always.

5. **The model API key is readable inside the sandbox, by design.** This is worth
   stating rather than implying otherwise. The CLI resolves its credential from
   `env.API_KEY` in the settings file and nowhere else, so the key has to be in the
   container, and the agent runs as the same user as the CLI — anything the CLI can
   read, the agent can read. Deepsand's `extra_env` passthrough *is* filtered, so an
   unrelated key cannot be smuggled in beside it, but the model key itself is not a
   secret from the agent and cannot be made one in this architecture. What the
   container buys is confinement, not secrecy: the sandbox is the only thing that
   can read it, and it can only send it to the model endpoint.

6. **Dialog spoofing through the request spool.** See
   [The request spool is not authenticated](#the-request-spool-is-not-authenticated)
   below: anything inside the sandbox can write a request, so the operator's
   decision is the control, and an operator who approves without reading the path is
   the attack.

7. **A filesystem metadata oracle on Docker Desktop.** `/workspace` is a
   `grpcfuse` share on Windows and macOS, and the share's jail checks content
   operations but not attribute lookups: a path component containing backslashes
   (`..\..\..\..\Windows`) is resolved by the share daemon as a Windows relative
   path, so `stat` on a guessed host path returns the real type, size and mtime even
   though `open`, `readdir` and every write are refused. Nothing is disclosed beyond
   existence, type, size and mtime, one guessed name at a time, and the mounts
   Deepsand chose are unaffected — but it does mean there is *a* path to host
   metadata outside the grants, which is why the instruction given to the contained
   model no longer claims that no such path exists. It is Docker's component and
   belongs upstream; it is recorded here so that nobody re-derives it as a Deepsand
   escape.

8. **The `full` network mode.** It does what it says. DeepCode can reach the
   host's own services. Filesystem isolation is unaffected, but this is why it is
   not the default and why choosing it produces a warning in the plan preview.

9. **A kernel or container-runtime escape.** Docker and the Linux kernel are the
   trust base. Deepsand reduces the attack surface (`--cap-drop=ALL`,
   `no-new-privileges`, read-only rootfs, resource limits) but cannot fix a
   kernel bug. Keeping Docker Desktop and the host OS updated is part of the
   security model, not an optional nicety.

10. **Hosts running without a container VM.** On Linux the daemon runs on the
    host, so a container escape is a host escape. Docker Desktop on Windows and
    macOS adds a VM boundary that Linux does not have. This is a real difference
    in defence in depth and is worth knowing.

### The hardened seccomp profile

`runtime/seccomp-hardened.json` is **attached by default** and `policy::plan_run`
applies it with `--security-opt=seccomp=<path>`. `impl Default for SeccompProfile`
returns `Hardened`, which is what a store without the field deserialises to, so
existing projects get it rather than Docker's built-in profile. The profile has 16
rules:

* 65 syscalls return `EPERM` outright: `mount`, `unshare`, `setns`, `pivot_root`,
  `chroot`, `bpf`, `perf_event_open`, `keyctl`, `kexec_*`, `init_module`,
  `open_by_handle_at`, `ptrace`, `process_vm_readv/writev`, `pidfd_getfd`, `kcmp`,
  `userfaultfd`, `io_uring_*`, the new mount API (`fsopen`, `fsconfig`, `fsmount`,
  `fspick`, `move_mount`, `open_tree`, `mount_setattr`), `reboot`, and friends.
* `clone3` returns `ENOSYS`, so glibc falls back to the argument-filterable
  `clone`.
* Eight `clone` rules deny `CLONE_NEWUSER`, `CLONE_NEWNS`, `CLONE_NEWPID`,
  `CLONE_NEWNET`, `CLONE_NEWIPC`, `CLONE_NEWUTS`, `CLONE_NEWCGROUP` and
  `CLONE_NEWTIME`. One rule per bit is required — several `args` entries inside one
  rule are ANDed, and `SCMP_CMP_MASKED_EQ` tests a single bit — so "any
  `CLONE_NEW*` flag" is expressible after all, as eight rules rather than one.
  `CLONE_NEWUSER` is the load-bearing one, because it needs no capability.
* Five `socket` rules reject exotic address families with `EAFNOSUPPORT`:
  `AF_PACKET`, `AF_TIPC`, `AF_ALG`, `AF_VSOCK` and `AF_XDP`, with `socketcall`
  refused outright. `AF_VSOCK` is the one that matters: on some configurations it
  is how a container reaches the host or the hypervisor.

**It fails closed.** If hardening is requested and the profile cannot be found,
`plan_run` returns an error instead of a plan, so a missing file stops the sandbox
rather than quietly weakening it.

**The profile applied is the profile the image carries.** The daemon resolves
`--security-opt=seccomp=` on the *host*, so the copy inside the image is only ever
read by an auditor, and the two can drift: round 3 of the escape assessment found a
container whose applied rules included the socket-family denials while the shipped
profile had no `socket` rule at all, which makes the hardening unattributable to the
artifact the project ships. The Dockerfile therefore writes the profile's SHA-256
beside it, and `seccomp::verify` compares that against the digest of the bytes about
to be handed to the daemon. A mismatch, a missing digest file or a malformed one is
a refusal, not a warning. `deepsandctl doctor` reports the result, per project.

That comparison is only worth anything if it checks the image the project actually runs,
and for a while it did not: the tag in settings is a *stem*, and the tools and the runtime
revision are appended to it, so the app built, labelled and digest-checked
`…-t<tools>-r<revision>` while the plan it handed to `docker run` named the bare stem. The
sandbox therefore ran whichever image that tag happened to hold -- a project's selected
tools were never the tools in its sandbox, and the revision that exists to force a rebuild
never reached a container. One derivation now feeds every call site
(`settings::settings_for_project`), and both the app and `deepsandctl` go through it.

**What a denylist cannot say, and the residual that follows.** Two things are not
expressible in this shape, and both are handled by enumeration rather than by a rule:

* "address family not in a set". Only registered families need a rule, because the
  kernel refuses an unregistered one by itself — but a kernel that registers a new
  dangerous family needs a new rule here.
* "any flag in a mask", in a single rule. Eight rules cover the eight namespace
  bits; one rule with a combined mask would instead mean "all of these bits set".

The durable answer to both is an allow-list (`defaultAction: DENY` plus the syscalls
the sandbox needs), which is what Docker's built-in profile is. This profile is a
denylist over an allow default, so a syscall that is not listed is *permitted* here
where Docker's built-in profile would refuse it. That is a real difference in
strength rather than a detail, and `crates/deepsand-core/tests/seccomp_profile.rs`
enumerates families and flags so that dropping one fails a test rather than a review.

## Verifying the claims

Everything above is asserted by tests you can run:

```bash
cargo test -p deepsand-core                   # 316 tests, including the seccomp, allowlist and durability claims
node runtime/scripts/test-mcp-bridge.mjs      # 55 checks: the permission protocol end to end
cargo test -p deepsand-core --test runtime_dockerfile   # claims about the image build, no Docker needed
```

The most load-bearing ones:

| Test | Claim |
| --- | --- |
| `a_plan_never_mounts_a_container_runtime_socket` | no socket, ever |
| `the_reply_channel_can_never_be_written_by_the_sandbox` | the `:ro` invariant |
| `a_writable_reply_channel_is_rejected_as_an_internal_error` | a bug cannot silently widen it |
| `only_the_workspace_and_grants_are_mounted_from_the_host_filesystem` | the mount list *is* the boundary |
| `the_workspace_is_validated_again_at_plan_time` | a repointed project cannot escape |
| `a_grant_that_became_forbidden_is_skipped_with_a_warning_not_mounted` | defence in depth on grants |
| `symlinks_are_resolved_before_guards_run` | link-based smuggling |
| `an_ancestor_of_home_is_refused`, `the_deepsand_state_directory_is_refused_both_ways` | the guard set |
| `local_and_private_addresses_are_never_targets` | the proxy cannot be aimed inward |
| `an_allowlisted_but_private_resolving_name_is_refused_while_its_literal_is_not` | rebinding is useless; naming the address is the deliberate exception |
| `a_path_that_only_looks_like_a_container_path_is_kept` | the guard is not over-broad (a Linux-breaking bug this caught) |
| `clone_is_refused_when_any_namespace_flag_is_set` | all eight `CLONE_NEW*` bits, not just the one that was remembered |
| `every_filtered_address_family_is_refused` | the socket-family set, and that `AF_UNIX`/`INET`/`INET6`/`NETLINK` survive |
| `the_ptrace_family_is_closed_including_pidfd_getfd` | the sibling of `ptrace` that was missing |
| `a_stale_image_is_refused_and_says_which_side_is_which` | the applied profile *is* the shipped profile (R3-A) |
| `the_runtime_revision_changes_when_any_input_changes` | the tag covers every image build input, so a rebuild cannot be skipped |
| `a_project_image_extends_the_base_tag_rather_than_replacing_it` | a plan names the project's image, never the stem |
| `a_project_settings_image_is_the_project_tag_and_nothing_else_moves` | one derivation, and it changes only the image |
| `a_request_is_never_answered_without_an_explicit_decision` | dialog spoofing cannot become a silent grant |
| `resolve_announces_what_it_dropped_rather_than_dropping_it_silently` | the env passthrough cannot smuggle an unrelated key in |
| `a_named_port_is_allowed_and_every_other_port_is_refused` | a port-qualified entry narrows rather than widens |
| `an_entry_without_a_port_covers_every_port` | the documented port semantics, asserted rather than implied |
| `a_named_address_reaches_private_space_where_a_hostname_may_not` | naming an address is the deliberate exception, and a name stays refused |
| `a_named_address_becomes_a_netfilter_allowance_and_its_port_a_publication` | an entry in the UI is an entry in the container, or it is a lie |
| `a_directory_inside_the_workspace_is_already_covered` | a request the sandbox did not need to make never reaches the operator |
| `a_write_request_for_a_read_only_grant_is_not_covered` | auto-refusal only where there is nothing left to decide |
| `a_state_file_that_cannot_be_opened_is_not_corruption` | a file that cannot be read is never moved aside, and never replaced with defaults |
| `a_nul_filled_state_file_falls_back_to_the_rolling_backup` | the torn write a power loss leaves behind |
| `a_valid_state_misjudged_as_corrupt_comes_back_by_itself` | the state that was wrongly set aside is rescued, not lost |
| `an_empty_rolling_backup_does_not_hide_a_set_aside_copy` | an empty fallback cannot stand in for a copy that has projects |
| `a_substitute_store_never_overwrites_the_rolling_backup` | an unreadable configuration cannot cost you the last good copy |
| `a_destination_that_never_answers_is_bounded_and_reported` | an allowlisted destination that swallows packets cannot tie the proxy up |
| `an_older_build_can_read_what_this_one_writes` | the on-disk mode name stays at the spelling older builds know |
| `both_mode_names_are_read_and_the_older_one_is_written` | the same property at the serde level, both directions |
| `a_state_file_from_a_newer_build_is_reported_and_left_alone` | a version skew is not corruption, and is not filed as it |
| `salvage_prefers_the_copy_with_the_most_projects` | among set-aside copies, the richest one wins |

To read the exact command a project would run:

```bash
deepsandctl plan <project>          # or the Activity tab's "Show the exact command"
```

One caveat, and it is the same in both places. A project in `allowlisted` or `none` mode
reaches the network only through the egress proxy, and the port that proxy listens on is
assigned when it starts, so the command genuinely does not exist until a proxy is up. Both
paths say so rather than showing a port that would not be the real one. In the app, start
the project once and ask again: the preview then names the proxy that is already running,
which is the one a further start reuses. `deepsandctl` cannot do that, because the proxy
belongs to the running app's process rather than to the CLI's.

A plan preview also describes one of two possible starts. Resuming an existing session adds
`--last` to the command inside the container, and the preview says so when a resumable
session exists; otherwise the command shown is the fresh-start one.

## Updates

The app updates itself, which is a capability worth being explicit about, because an
update is arbitrary code on the host — the one thing all of the rest of this document is
arranged to prevent the *sandbox* from doing.

Three properties hold it in place:

* **The signature is the control, not the transport.** The updater verifies a minisign
  signature against the public key pinned in `src-tauri/tauri.conf.json` before it
  installs anything. HTTPS is how the bytes arrive; the signature is what decides whether
  they are installed. A hijacked repository, a compromised GitHub account, or a rewritten
  release cannot produce an update that installs, because none of those have the private
  key. This is also why the private key is treated in `AGENTS.md` as a code-signing
  certificate rather than a build artifact.
* **The sandbox cannot ask for an update, and cannot reach the updater.** The updater
  plugin is initialised in Rust and the webview is given no `updater:*` permission; the
  only paths are two commands of ours, and both refuse to do anything in a development
  build. The command surface a remote client may use is a separate, explicit table in
  `crates/deepsand-core/src/remote.rs`, and neither command appears in it — a stolen
  remote token must not be able to replace the binary on the host it reached.
* **Installing is an operator action, and is described before it happens.** The app
  checks, says what it found, and waits. Nothing downloads or installs without a click,
  and the dialog names the sandboxes that restarting will stop, because that is the real
  cost of pressing the button.

The residual, stated plainly: a build that is *older* than a release will happily install
that release, including one that changed behaviour you relied on. There is no pinning and
no update channel selection. If you need a build that does not move, build from source at
the commit you want rather than installing a release.

## Secrets

Secrets are encrypted at rest and injected as environment variables. What that does
and does not buy you is worth being precise about.

**Encrypted with ChaCha20-Poly1305**, keyed from the operating system's keystore
(DPAPI, Keychain, Secret Service) through `keyring`. A fresh nonce per save, and the
ciphertext is authenticated, so a modified file is rejected rather than read.

**What this protects.** A copy of the data directory, a synced folder, a backup, a
support bundle. The *file* travels further than the process does, which is the whole
reason it is worth encrypting.

**What it does not protect.** Anything running as you. That process can ask the
keystore for the key exactly as Deepsand does. This is confidentiality at rest, not a
boundary. The boundary is the container.

**`DEEPSAND_SECRETS_KEY`** is a fallback for a machine with no usable keystore. It is
the same threat model as writing the key beside the ciphertext, it is never chosen
silently, and it is opt-in by setting the variable.

Three deliberate choices, each closing a specific hole:

- **`--env-file`, never `-e`.** `docker run -e NAME=value` puts the value in the
  process argument list, where any local user can read it with `ps`. The environment
  file is written 0600 and read by the docker client. There is a test asserting no
  value-shaped `--env` pair can appear in a plan.
- **Reserved names are refused.** `PATH`, `HOME`, `LD_PRELOAD`, `NODE_OPTIONS`,
  `PYTHONPATH` and anything starting with `DEEPSAND_` cannot be a secret name, so a
  secret cannot become a way to change how the sandbox itself behaves.
- **Values are redacted from output** before it leaves the host, covering the
  desktop terminal and any remote subscriber identically.

Two limits, stated rather than hidden:

- Redaction works **per output chunk**, and a PTY read can split arbitrarily, so a
  value straddling a boundary could in principle pass through. It is also fixed at
  session start, so a secret added mid-session is covered from the next start.
- Nothing written **into a file in the workspace** is redacted. Redaction covers the
  stream, not the filesystem.

The interface never receives a value: secret listings carry names and lengths only, so
there is no reveal control that could be left on or captured in a screenshot.

## Reporting a problem

If you find a way out, that is the most valuable thing you can send. Please
include the project's plan output (`deepsandctl plan <project>`) and the exact
steps, since the plan is the complete statement of the sandbox's shape.
