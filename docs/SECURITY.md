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
`restricted` mode.

`restricted` mode additionally allows exactly one address: the Deepsand proxy on
the project's own bridge gateway. The proxy:

* matches hostnames against the operator's allowlist (exact, or `*.suffix`)
* refuses ports other than 80 and 443
* **resolves names itself** and refuses any result in loopback, private,
  link-local, CGNAT or reserved space

That last point matters: an allowlisted hostname that resolves to `192.168.1.1`
— whether by DNS rebinding, a hostile DNS server, or a `hosts` entry — is
refused, so the allowlist cannot be turned into a route onto the local network.

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

## What this does *not* protect against

Being explicit here is more useful than a longer list of things it does.

1. **The operator approving something they should not.** The guards stop the
   worst cases, but granting read-write access to a directory full of secrets is
   a decision only the operator can get right. The dialog names the exact path,
   defaults to read-only, and never inherits a write request.

2. **Model API exfiltration in the default network mode.** In `internet` mode the
   sandbox can reach the public internet, so anything it can read, it can send
   to a remote host. This is inherent to using a hosted model. Use `restricted`
   mode with a short allowlist to close it.

3. **`internet` mode does not filter by domain.** It blocks *address ranges*. A
   public pastebin is reachable. `restricted` mode is the answer.

4. **Leaked credentials via the project directory.** The API key is injected into
   the container's own home volume, not the project, but a careless setup could
   still put a secret in the workspace: the sandbox can read everything in
   `/workspace`, always.

5. **The `full` network mode.** It does what it says. DeepCode can reach the
   host's own services. Filesystem isolation is unaffected, but this is why it is
   not the default and why choosing it produces a warning in the plan preview.

6. **A kernel or container-runtime escape.** Docker and the Linux kernel are the
   trust base. Deepsand reduces the attack surface (`--cap-drop=ALL`,
   `no-new-privileges`, read-only rootfs, resource limits) but cannot fix a
   kernel bug. Keeping Docker Desktop and the host OS updated is part of the
   security model, not an optional nicety.

7. **Hosts running without a container VM.** On Linux the daemon runs on the
   host, so a container escape is a host escape. Docker Desktop on Windows and
   macOS adds a VM boundary that Linux does not have. This is a real difference
   in defence in depth and is worth knowing.

### The hardened seccomp profile

`runtime/seccomp-hardened.json` is **attached by default**. `impl Default for
SeccompProfile` returns `Hardened`, which is what a store without the field
deserialises to, so existing projects get hardening rather than Docker's
permissive built-in profile. Docker's built-in profile is already good, so this
is an *additive* denylist on top, and `policy::plan_run` attaches it with
`--security-opt=seccomp=<path>`:

* 56 syscalls return `EPERM`: `mount`, `unshare`, `setns`, `pivot_root`,
  `chroot`, `bpf`, `perf_event_open`, `keyctl`, `kexec_*`, `init_module`,
  `open_by_handle_at`, `ptrace`, `process_vm_readv/writev`, `userfaultfd`,
  `io_uring_*`, `reboot`, and friends.
* `clone3` returns `ENOSYS`, so glibc falls back to the argument-filterable
  `clone`.
* Five `socket` rules reject exotic address families with `EAFNOSUPPORT`:
  `AF_PACKET`, `AF_TIPC`, `AF_ALG`, `AF_VSOCK` and `AF_XDP`, with `socketcall`
  refused outright. `AF_VSOCK` is the one that matters: on some configurations it
  is how a container reaches the host or the hypervisor.

**It fails closed.** If hardening is requested and the profile cannot be found,
`plan_run` returns an error instead of a plan, so a missing file stops the sandbox
rather than quietly weakening it.

**Known deviation, stated plainly.** With `defaultAction: ALLOW` the profile
cannot express Docker's "deny `clone()` when any `CLONE_NEW*` flag is set" rule,
because `SCMP_CMP_MASKED_EQ` only tests single-bit equality in that direction.
The containment argument does not depend on it — a nested user namespace grants
`CAP_SYS_ADMIN` only *inside* that namespace, where it can at most remount its own
namespace's view of the same read-only mounts. But it is a deviation, and it is
documented here rather than glossed over.

## Verifying the claims

Everything above is asserted by tests you can run:

```bash
cargo test -p deepsand-core                   # 233 tests: paths, policy, broker, proxy, secrets
node runtime/scripts/test-mcp-bridge.mjs      # 47 checks: the permission protocol end to end
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
| `an_allowlisted_but_private_resolving_host_is_refused` | rebinding is useless |
| `a_path_that_only_looks_like_a_container_path_is_kept` | the guard is not over-broad (a Linux-breaking bug this caught) |

To read the exact command for any project:

```bash
deepsandctl plan <project>          # or the Activity tab's "Show the exact command"
```

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
