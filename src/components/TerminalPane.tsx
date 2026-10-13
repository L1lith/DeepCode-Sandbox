/**
 * The terminal pane.
 *
 * A real xterm.js terminal wired to the PTY that the Rust side keeps inside the
 * container. Two details matter for a full-screen TUI:
 *
 *  * Output arrives base64-encoded and is written as a `Uint8Array`, so the
 *    byte stream is never mangled by UTF-8 decoding at a chunk boundary.
 *  * xterm.js answers terminal queries such as ConPTY's cursor-position request
 *    itself, which is what lets the container's TUI initialise at all.
 */

import { createEffect, createSignal, onCleanup, onMount, Show } from "solid-js";
import { Terminal } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import { WebLinksAddon } from "@xterm/addon-web-links";
import "@xterm/xterm/css/xterm.css";
import * as api from "../lib/api";
import { attachTerminal, describeError, selectedProject, store, toast } from "../store";

export function TerminalPane() {
  let host!: HTMLDivElement;
  let term: Terminal | undefined;
  let fit: FitAddon | undefined;
  const [busy, setBusy] = createSignal(false);

  const project = () => selectedProject();

  onMount(() => {
    term = new Terminal({
      fontFamily:
        'ui-monospace, "SF Mono", "Cascadia Mono", "JetBrains Mono", Menlo, Consolas, monospace',
      fontSize: 13,
      lineHeight: 1.25,
      cursorBlink: true,
      scrollback: 8000,
      allowProposedApi: true,
      theme: {
        background: "#0a0c11",
        foreground: "#dfe3ee",
        cursor: "#4d6bfe",
        selectionBackground: "#2f365080",
        black: "#1b1f2a",
        red: "#ff6b6b",
        green: "#3ddc97",
        yellow: "#ffc857",
        blue: "#4d6bfe",
        magenta: "#c792ea",
        cyan: "#5ad4e6",
        white: "#e6e9f2",
      },
    });
    fit = new FitAddon();
    term.loadAddon(fit);
    term.loadAddon(new WebLinksAddon());
    term.open(host);

    // Fit on the next frame, not inline. `onMount` runs while the element exists but
    // may not have its final box yet, and a fit against a box that is too tall leaves
    // xterm believing the whole buffer already fits on screen: the scrollback exists,
    // the wheel does nothing, and resizing anything fixes it. Measuring after layout is
    // what makes the wheel work the first time.
    const firstFit = window.requestAnimationFrame(() => safeFit());

    // Keystrokes go straight to the container.
    const dataSub = term.onData((data) => {
      const current = project();
      if (!current) return;
      api.writeToSession(current.id, data).catch((error) => {
        // Losing a keystroke when the container has just exited is expected.
        if (!/no sandbox is running/i.test(describeError(error))) {
          toast("warn", "Could not send input", describeError(error));
        }
      });
    });

    // Keep the PTY the same size as the pane. The observer covers the pane's own box
    // changing; the window listener covers the case the observer cannot see, such as
    // the pane being hidden and shown again while the window itself is resized.
    const observer = new ResizeObserver(() => safeFit());
    observer.observe(host);
    const onWindowResize = () => safeFit();
    window.addEventListener("resize", onWindowResize);

    onCleanup(() => {
      window.cancelAnimationFrame(firstFit);
      window.removeEventListener("resize", onWindowResize);
      observer.disconnect();
      dataSub.dispose();
      term?.dispose();
    });
  });

  function safeFit() {
    if (!fit || !term || !host) return;
    // A hidden pane has no box, and fitting to zero produces a one-row terminal that
    // then has to be corrected. Doing nothing is correct: the resize observer fires
    // when the pane is shown again.
    if (host.clientWidth === 0 || host.clientHeight === 0) return;
    try {
      fit.fit();
      const current = project();
      if (current) {
        void api.resizeSession(current.id, term.rows, term.cols).catch(() => undefined);
      }
    } catch {
      /* the pane can be zero-sized during layout; nothing to do */
    }
  }

  // Re-attach when the selected project changes, clearing the old buffer.
  createEffect(() => {
    const current = project();
    if (!term) return;
    term.reset();
    if (!current) return;

    const detach = attachTerminal(current.id, (bytes) => term?.write(bytes));
    onCleanup(detach);

    // Ask the container to repaint by nudging the PTY size: a TUI re-renders on
    // SIGWINCH, which is how the operator sees their session again after a tab
    // switch rather than a blank screen.
    window.setTimeout(() => safeFit(), 30);
  });

  async function run() {
    const current = project();
    if (!current) return;
    setBusy(true);
    try {
      await api.startSession(current.id, true);
      toast("ok", `Started ${current.name}`);
      window.setTimeout(() => safeFit(), 120);
    } catch (error) {
      toast("error", "Could not start the sandbox", describeError(error));
    } finally {
      setBusy(false);
    }
  }

  async function stop() {
    const current = project();
    if (!current) return;
    setBusy(true);
    try {
      await api.stopSession(current.id);
    } catch (error) {
      toast("error", "Could not stop the sandbox", describeError(error));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div class="panel-flush">
      <div class="terminal-wrap">
        <div class="terminal-host" ref={host} />
        <Show when={!project()?.running}>
          <div class="terminal-overlay">
            <Show
              when={project()}
              fallback={
                <>
                  <h3>No project selected</h3>
                  <p>Create a project to give DeepCode a working directory and a sandbox to run in.</p>
                </>
              }
            >
              {(current) => (
                <>
                  <h3>{current().name} is not running</h3>
                  <Show when={!current().workspaceExists}>
                    <div class="callout callout-danger">
                      The working directory <span class="mono">{current().rootDir}</span> does not exist any more.
                      Remove the project or recreate the folder.
                    </div>
                  </Show>
                  <Show when={store.info && !store.info.docker.available}>
                    <div class="callout callout-danger">
                      The Docker daemon is not reachable. Start Docker Desktop, then try again.
                    </div>
                  </Show>
                  <Show when={store.info && store.info.docker.available && !store.info.docker.image_present}>
                    <div class="callout callout-warn">
                      The runtime image <span class="mono">{store.info?.settings.image}</span> has not been built
                      yet. Build it from the Activity tab, or run{" "}
                      <span class="mono">node runtime/scripts/build-image.mjs</span>.
                    </div>
                  </Show>
                  <p>
                    DeepCode will run inside a container whose only view of this machine is{" "}
                    <span class="mono">{current().rootDir}</span>
                    {current().grantCount > 0
                      ? ` plus ${current().grantCount} shared director${current().grantCount === 1 ? "y" : "ies"}`
                      : ""}
                    .
                  </p>
                  <button class="btn btn-primary" disabled={busy()} onClick={() => void run()}>
                    Run project
                  </button>
                </>
              )}
            </Show>
          </div>
        </Show>
      </div>
      <Show when={project()?.running}>
        <div class="queue-note">
          <span>
            Container <span class="mono">{project()?.containerName}</span> is running. Everything it can see is
            listed under Permissions.
          </span>
          <button class="btn btn-sm" disabled={busy()} onClick={() => void stop()}>
            Stop
          </button>
        </div>
      </Show>
    </div>
  );
}
