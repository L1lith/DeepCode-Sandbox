#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Deepsand container entrypoint.
#
# Responsibilities, in order:
#   1. Materialise the host-generated DeepCode settings into $HOME.
#   2. Apply the egress policy (so a `--cap-add NET_ADMIN` container still
#      cannot reach the host or the LAN, depending on the requested mode).
#   3. Make the session-state volume usable by the sandbox user.
#   4. Irreversibly drop every capability, the bounding set, and uid 0.
#   5. exec the requested command.
#
# Every security-relevant step is fail-closed: if it cannot be completed the
# container exits non-zero rather than running under-weakened.
#
# ---------------------------------------------------------------------------
# Two things about ownership that are easy to get wrong here.
#
# First: this container runs with `--cap-drop=ALL --cap-add=CHOWN
# --cap-add=SETUID --cap-add=SETGID`, so CapEff is 0xc1. That contains CAP_CHOWN
# but *not* CAP_DAC_OVERRIDE, which means root in here is still bound by file
# permission bits. The obvious `install -d -m 0700 -o U -g G <dir>` fails twice
# over: the volume driver refuses `chmod` on a mount root ("Operation not
# permitted") even as root holding CAP_CHOWN, and if it *did* succeed it would
# leave a directory owned by the sandbox user with mode 0700 -- in which root,
# being "other", has no write permission at all.
#
# So the order is deliberate: create the directory, take ownership of it as
# root, copy the settings in, and only *then* hand it to the sandbox user. The
# copy must happen while the directory is still ours.
#
# Second: because none of those ownership operations can be relied upon, this
# script never treats one as authoritative. It performs the ones that work,
# tolerates the ones that cannot, and then verifies the property that actually
# matters -- that the sandbox user can read its credentials and write its
# session history. A failure there stops the container with an explanation
# instead of starting a sandbox that cannot work.
# ---------------------------------------------------------------------------
set -uo pipefail

DEEPSAND_LIB=/usr/local/lib/deepsand
TARGET_USER="${DEEPSAND_UID:-1000}"
TARGET_GROUP="${DEEPSAND_GID:-1000}"
NET_MODE="${DEEPSAND_NETWORK_MODE:-internet}"
NETFILTER_OPTIONAL="${DEEPSAND_NETFILTER_OPTIONAL:-0}"
HOME_DIR=/home/deepcode
DEEPCODE_DIR="$HOME_DIR/.deepcode"
REQUESTS_DIR=/deepsand/ipc/requests

log()  { printf '[deepsand] %s\n' "$*" >&2; }
warn() { printf '[deepsand] WARNING: %s\n' "$*" >&2; }
fail() { printf '[deepsand] FATAL: %s\n' "$*" >&2; exit 1; }

# Run a command as the sandbox user. Usability is always verified as the user who
# will actually have to do the work, never inferred from ownership.
as_target() {
  setpriv --reuid="$TARGET_USER" --regid="$TARGET_GROUP" --clear-groups "$@"
}

START_UID="$(id -u)"
if [ "$START_UID" = "0" ]; then
  AS_ROOT=1
else
  AS_ROOT=0
  warn "started as uid $START_UID rather than root; ownership and egress setup cannot run"
fi

# ---------------------------------------------------------------------------
# 1. Session state volume
# ---------------------------------------------------------------------------
if ! mkdir -p "$DEEPCODE_DIR" 2>/dev/null; then
  fail "could not create $DEEPCODE_DIR. The session-state volume is missing or not writable."
fi

if [ "$AS_ROOT" = "1" ]; then
  # Take ownership so that the copies below can actually happen. See the note at
  # the top of this file: root here lacks CAP_DAC_OVERRIDE, so it cannot write
  # into a directory owned by the sandbox user.
  chown 0:0 "$DEEPCODE_DIR" 2>/dev/null || true
  chmod 0755 "$DEEPCODE_DIR" 2>/dev/null || true
  if ! touch "$DEEPCODE_DIR/.deepsand-write-probe" 2>/dev/null; then
    fail "$DEEPCODE_DIR is not writable by root inside this container, so DeepCode's
  settings and session history could not be prepared. This is usually a named-volume
  problem. Try removing the volume and starting the project again:
      docker volume rm deepsand-state-<project>"
  fi
  rm -f "$DEEPCODE_DIR/.deepsand-write-probe" 2>/dev/null || true
fi

# Copy a host-provided file into the sandbox home, then give it to the sandbox
# user. Returns non-zero if the copy itself failed, so the caller can explain.
#
# The write goes to a staging name and is then renamed into place, rather than
# copied straight over the destination. That is not a style preference: `place_file`
# chowns the destination to the sandbox user, so on every run after the first the
# destination exists owned by `$TARGET_USER` with mode 0600. Root in this container
# has no CAP_DAC_OVERRIDE and is not the owner, so `cp` over that file fails with
# EACCES -- meaning the first run of a project worked and every subsequent run died
# with "could not write .../settings.json even though the source exists".
#
# Writing to a fresh name sidesteps the permission on the destination entirely, and
# the rename needs only write permission on the directory, which root does have.
# It also means a reader never sees a half-written credentials file.
place_file() {
  local src="$1" dst="$2" mode="$3" staged="$2.deepsand-new"
  rm -f "$staged" 2>/dev/null || true
  if ! cp "$src" "$staged" 2>/dev/null; then
    return 1
  fi
  if [ "$AS_ROOT" = "1" ]; then
    chown "$TARGET_USER:$TARGET_GROUP" "$staged" 2>/dev/null || true
    chmod "$mode" "$staged" 2>/dev/null || true
  fi
  if ! mv -f "$staged" "$dst" 2>/dev/null; then
    rm -f "$staged" 2>/dev/null || true
    return 1
  fi
  return 0
}

# The credentials file is not optional. Without it DeepCode cannot talk to a
# model at all, so a sandbox that starts anyway would just be a confusing dead
# end. Deepsand's own UI already refuses to start a project with no API key, so
# a missing file here means something is wrong with the mount.
if [ ! -f /etc/deepsand/settings.json ]; then
  fail "DeepCode's configuration did not reach the container: /etc/deepsand/settings.json
  is not a readable file.

  Deepsand bind-mounts <data>/projects/<id>/config at /etc/deepsand. If that
  directory is empty inside the container, the host file sharing is not in
  effect for it. On Docker Desktop, add the drive that holds your projects under
  Settings -> Resources -> File Sharing and restart Docker. Run
  'deepsandctl doctor' for a direct check."
fi

if place_file /etc/deepsand/settings.json "$DEEPCODE_DIR/settings.json" 0600; then
  log "installed settings.json"
else
  fail "could not write $DEEPCODE_DIR/settings.json even though the source exists.
  $DEEPCODE_DIR is owned by $(stat -c '%U:%G %a' "$DEEPCODE_DIR" 2>/dev/null || echo '?') and
  this container runs without CAP_DAC_OVERRIDE, so ownership has to be handed over
  in the right order. Please report this with the output of 'docker run --rm
  --entrypoint sh <image> -c \"ls -la /home/deepcode/.deepcode\"'."
fi

# Standing instructions are a nicety rather than a hard requirement: without them
# the sandbox still works, it just has to discover its own shape.
if [ -f /etc/deepsand/AGENTS.md ]; then
  if place_file /etc/deepsand/AGENTS.md "$DEEPCODE_DIR/AGENTS.md" 0644; then
    log "installed AGENTS.md"
  else
    warn "could not install AGENTS.md; DeepCode will not receive its standing instructions"
  fi
else
  warn "/etc/deepsand/AGENTS.md is absent; DeepCode will not receive its standing instructions"
fi

# Hand the directory over to the sandbox user now that the writes are done.
if [ "$AS_ROOT" = "1" ]; then
  chown "$TARGET_USER:$TARGET_GROUP" "$DEEPCODE_DIR" 2>/dev/null || true
  chmod 0700 "$DEEPCODE_DIR" 2>/dev/null || true
fi

# ---------------------------------------------------------------------------
# 2. Egress policy
# ---------------------------------------------------------------------------
if [ "$AS_ROOT" = "0" ]; then
  warn "egress policy NOT applied"
  if [ "$NETFILTER_OPTIONAL" != "1" ]; then
    fail "network mode '$NET_MODE' requires the egress policy, but this container is not root. Refusing to run under-weakened."
  fi
elif ! "$DEEPSAND_LIB/netfilter.sh" "$NET_MODE"; then
  if [ "$NETFILTER_OPTIONAL" = "1" ]; then
    warn "egress policy failed but DEEPSAND_NETFILTER_OPTIONAL=1; continuing unenforced"
  else
    fail "egress policy for mode '$NET_MODE' could not be applied; refusing to run under-weakened"
  fi
fi

# ---------------------------------------------------------------------------
# 3. Verify the sandbox user can actually work
# ---------------------------------------------------------------------------
if [ "$AS_ROOT" = "1" ]; then
  if ! as_target test -r "$DEEPCODE_DIR/settings.json"; then
    fail "uid $TARGET_USER cannot read $DEEPCODE_DIR/settings.json, so DeepCode would start
  with no credentials. Ownership of the session volume has gone wrong; removing it
  (docker volume rm deepsand-state-<project>) and starting again should fix it."
  fi
  if ! as_target test -w "$DEEPCODE_DIR"; then
    fail "uid $TARGET_USER cannot write $DEEPCODE_DIR, so DeepCode could not save session
  history and your conversation would be lost on every restart. Remove the volume
  (docker volume rm deepsand-state-<project>) and start the project again."
  fi
  log "credentials readable and session volume writable by uid $TARGET_USER"
fi

# The request spool is the sandbox's only way to ask for more permissions. It is
# a bind mount of a host directory, and on some host filesystems it arrives
# root-owned and unwritable by the sandbox user.
if [ -d "$REQUESTS_DIR" ]; then
  if [ "$AS_ROOT" = "1" ]; then
    chown "$TARGET_USER:$TARGET_GROUP" "$REQUESTS_DIR" 2>/dev/null || true
    chmod 0777 "$REQUESTS_DIR" 2>/dev/null || true
  fi
  if ! as_target test -w "$REQUESTS_DIR"; then
    warn "$REQUESTS_DIR is not writable by uid $TARGET_USER."
    warn "DeepCode will not be able to ask you for extra permissions at all this session."
    warn "The sandbox still cannot escape; you simply will not receive its requests."
  fi
fi

# ---------------------------------------------------------------------------
# 4. Posture banner, so the operator can see the shape of the sandbox at a glance
# ---------------------------------------------------------------------------
ROOTFS=$([ -w / ] && echo writable || echo read-only)
log "sandbox up: uid=$TARGET_USER net=$NET_MODE workspace=$(pwd) rootfs=$ROOTFS"
log "grants: $(find /grants -mindepth 1 -maxdepth 1 2>/dev/null | wc -l) mounted path(s) under /grants"

# ---------------------------------------------------------------------------
# 4b. The virtual display, when this image has one
#
# Started only when Xvfb is in the image, which is to say when the tool was chosen for this
# project -- there is no separate switch, so the display cannot be believed in and absent.
#
# It runs as the sandbox user, on the display's own socket, with -nolisten tcp so there is no
# TCP port for anything outside this container to be reached on. -ac turns off X11 access
# control, which is what lets any process in here connect without an xauth cookie. That is
# safe for a reason that does not generalise: every process that can reach this socket is
# already a process the sandbox is running, and the other end is a memory buffer in this
# container rather than the operator's screen.
# ---------------------------------------------------------------------------
if command -v Xvfb >/dev/null 2>&1; then
  DISPLAY=:99
  export DISPLAY
  # Through the same script the agent uses to resize it, so the startup size and a later
  # change go down one path. It runs as the sandbox user either way; the display needs no
  # privileges, and giving it any would be a reason for it to exist.
  if [ "$AS_ROOT" = "1" ]; then
    setpriv \
      --reuid="$TARGET_USER" \
      --regid="$TARGET_GROUP" \
      --clear-groups \
      --inh-caps=-all \
      --ambient-caps=-all \
      --bounding-set=-all \
      --no-new-privs \
      "$(dirname "$0")/deepsand-display.sh" 1440x900 || true
  else
    "$(dirname "$0")/deepsand-display.sh" 1440x900 || true
  fi
  log "virtual display: $DISPLAY (run 'deepsand-display 1920x1080' to change the size)"
fi

# ---------------------------------------------------------------------------
# 5. Drop everything and exec
# ---------------------------------------------------------------------------
if [ "$AS_ROOT" = "1" ]; then
  exec setpriv \
      --reuid="$TARGET_USER" \
      --regid="$TARGET_GROUP" \
      --clear-groups \
      --inh-caps=-all \
      --ambient-caps=-all \
      --bounding-set=-all \
      --no-new-privs \
      "$@"
fi

exec "$@"
