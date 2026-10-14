#!/usr/bin/env bash
# Start, restart or resize the virtual display.
#
# The agent runs this. The display is the sandbox's own screen, so resizing it is a decision
# about this container and nothing else -- there is no host screen to disturb, and no
# permission worth asking for between one size and another.
#
#   deepsand-display            show what is running
#   deepsand-display 1920x1080  restart it at that size
#   deepsand-display off        stop it without stopping the sandbox
#
# Resizing restarts the server, so anything already drawing into the display loses its
# connection and has to be started again. That is the honest cost of changing the size of a
# screen, and it is why the default is a size that is usually good enough.
set -uo pipefail

SIZE="${1:-}"
DISPLAY_NUM=:99
SOCKET=/tmp/.X11-unix/X99

usage() {
  echo "usage: deepsand-display [WIDTHxHEIGHT | off | status]" >&2
  echo "  for example: deepsand-display 1920x1080" >&2
  exit 2
}

running() {
  pgrep -f "Xvfb ${DISPLAY_NUM}" >/dev/null 2>&1
}

if ! command -v Xvfb >/dev/null 2>&1; then
  echo "this image has no virtual display. Ask the operator for the tool" >&2
  echo "'Virtual display (Xvfb)' and it will be built in on the next start." >&2
  exit 3
fi

case "$SIZE" in
  ""|status)
    if running; then
      if command -v xdpyinfo >/dev/null 2>&1 && [ -e "$SOCKET" ]; then
        echo "virtual display ${DISPLAY_NUM} is up: $(DISPLAY=${DISPLAY_NUM} xdpyinfo | awk '/dimensions/ {print $2}')"
      else
        echo "virtual display ${DISPLAY_NUM} is up"
      fi
    else
      echo "virtual display is not running. Start it with: deepsand-display 1440x900"
    fi
    exit 0
    ;;
  off|stop)
    pkill -f "Xvfb ${DISPLAY_NUM}" >/dev/null 2>&1 || true
    echo "virtual display stopped"
    exit 0
    ;;
esac

# Anything that is not a size is a mistake worth naming rather than passing to Xvfb, which
# would fail in a way that reads like the display is broken.
case "$SIZE" in
  [0-9]*x[0-9]*) ;;
  *) usage ;;
esac
WIDTH="${SIZE%%x*}"
HEIGHT="${SIZE##*x}"
case "$WIDTH$HEIGHT" in
  *[!0-9]*) usage ;;
esac
# The largest texture a typical GPU-less X server here can be asked for without falling over
# is not something to guess at, so the range is checked and explained instead.
if [ "$WIDTH" -lt 320 ] || [ "$HEIGHT" -lt 240 ] || [ "$WIDTH" -gt 7680 ] || [ "$HEIGHT" -gt 4320 ]; then
  echo "$SIZE is outside the range this display accepts (320x240 up to 7680x4320)" >&2
  exit 2
fi

mkdir -p /tmp/.X11-unix 2>/dev/null || true

if running; then
  pkill -f "Xvfb ${DISPLAY_NUM}" >/dev/null 2>&1 || true
  # Waited for, not slept at: an Xvfb that is still shutting down holds the socket, and a new
  # server that finds it taken refuses to start.
  for _ in $(seq 1 25); do
    running || break
    sleep 0.2
  done
fi

Xvfb "${DISPLAY_NUM}" -screen 0 "${SIZE}x24" -ac -nolisten tcp >/tmp/xvfb.log 2>&1 &

for _ in $(seq 1 25); do
  [ -e "$SOCKET" ] && break
  sleep 0.2
done

if [ -e "$SOCKET" ]; then
  echo "virtual display ${DISPLAY_NUM} is up at ${SIZE}"
  exit 0
fi
echo "the display did not come up at ${SIZE}; see /tmp/xvfb.log" >&2
exit 1
