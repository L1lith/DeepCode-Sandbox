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
import { attachTerminal, describeError, selectedProject, sessionOperation, store, toast } from "../store";

export function TerminalPane() {
  let host!: HTMLDivElement;
  let term: Terminal | undefined;
  let fit: FitAddon | undefined;
  // The button state lives in the store now: the header's Run and this one both act on the
  // same project, and when each kept its own copy a failed run could leave this one greyed
  // out for good while the header's was fine.
  const busy = () => store.sessionBusy === project()?.id;

  const project = () => selectedProject();

  /** True while a dragged file is over the terminal. */
  const [dropping, setDropping] = createSignal(false);
  /** True while something is being copied into the sandbox. */
  const [attaching, setAttaching] = createSignal(false);

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

    // Pasting into a terminal is where a webview loses the clipboard's *files*: the keystroke
    // goes to the TUI and an image is never mentioned to anybody. This intercepts a paste that
    // carries files -- text is left to xterm, which already inserts it -- copies them into the
    // sandbox and types the path, which is what the CLI can read. Capture phase, so this is seen
    // before xterm's own listener on the textarea inside.
    const onPaste = (event: ClipboardEvent) => {
      const files = Array.from(event.clipboardData?.items ?? [])
        .filter((item) => item.kind === "file")
        .map((item) => item.getAsFile())
        .filter((file): file is File => file !== null);
      if (files.length === 0) return;
      event.preventDefault();
      event.stopPropagation();
      void attachFiles(files);
    };
    host.addEventListener("paste", onPaste, true);

    // Dropped files: Tauri hands over the paths, so the pane has to say whether the drop landed
    // on it. Positions arrive in physical pixels, which is why they are scaled before being
    // compared with a layout rectangle.
    let unlistenDrop: (() => void) | undefined;
    void api
      .onDragDrop((payload) => {
        if (payload.kind === "leave") {
          setDropping(false);
          return;
        }
        // The whole pane, not only the xterm element: the overlay and its Run button are part
        // of the terminal as far as an operator is concerned, and a drop there should land.
        const wrap = host.closest(".terminal-wrap") ?? host;
        const rect = wrap.getBoundingClientRect();
        const scale = window.devicePixelRatio || 1;
        const x = payload.x / scale;
        const y = payload.y / scale;
        const inside = x >= rect.left && x <= rect.right && y >= rect.top && y <= rect.bottom;
        if (payload.kind === "over") {
          setDropping(inside);
          return;
        }
        setDropping(false);
        if (inside) void attachDroppedPaths(payload.paths);
      })
      .then((unlisten) => {
        unlistenDrop = unlisten;
      })
      .catch(() => {
        /* A platform without drag-and-drop is not a reason to fail to mount. */
      });

    onCleanup(() => {
      window.cancelAnimationFrame(firstFit);
      window.removeEventListener("resize", onWindowResize);
      host.removeEventListener("paste", onPaste, true);
      unlistenDrop?.();
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
  /**
   * How many of the build's lines have been written to the terminal.
   *
   * The build log used to live only in the Activity tab's panel, which is the wrong place to be
   * looking when you have just pressed Run and a terminal is what you are watching. These are
   * the same lines, written before the PTY exists; when it does, its output carries on below
   * them, so the whole thing reads as one session: the tools, then DeepCode.
   */
  let mirrored = 0;
  let mirroring = false;

  createEffect(() => {
    const lines = store.buildLog;
    const building = store.building;

    if (!building) {
      // The next build starts its log over; so does the count of what has been shown.
      if (lines.length === 0) {
        mirrored = 0;
        mirroring = false;
      }
      return;
    }
    if (!term) return;
    if (lines.length < mirrored) mirrored = 0;

    if (!mirroring) {
      // A previous run's scrollback is not what this is about, and the tools being installed are
      // the only thing worth reading until they are done.
      term.reset();
      term.writeln("\x1b[2m── installing tools for this project ──\x1b[0m");
      mirrored = 0;
      mirroring = true;
    }
    for (let index = mirrored; index < lines.length; index += 1) {
      // Dim: this is the install talking, not the agent.
      term.writeln(`\x1b[2m${lines[index] ?? ""}\x1b[0m`);
    }
    mirrored = lines.length;
  });

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
    await sessionOperation(current.id, async () => {
      try {
        await api.startSession(current.id, true);
        toast("ok", `Started ${current.name}`);
        window.setTimeout(() => safeFit(), 120);
      } catch (error) {
        toast("error", "Could not start the sandbox", describeError(error));
      }
    });
  }

  async function stop() {
    const current = project();
    if (!current) return;
    await sessionOperation(current.id, async () => {
      try {
        await api.stopSession(current.id);
      } catch (error) {
        toast("error", "Could not stop the sandbox", describeError(error));
      }
    });
  }

  /* ----------------------------------------------------------------------- */
  /* Attachments                                                             */
  /* ----------------------------------------------------------------------- */

  /** Matches the backend's limit, so the refusal is immediate rather than after a long read. */
  const ATTACH_LIMIT_BYTES = 25 * 1024 * 1024;

  /**
   * A file's bytes as base64, in chunks.
   *
   * `String.fromCharCode(...bytes)` on a whole screenshot is a stack overflow, which is a
   * memorable way to fail to paste a picture.
   */
  async function fileToBase64(file: File): Promise<string> {
    const bytes = new Uint8Array(await file.arrayBuffer());
    let binary = "";
    const CHUNK = 0x8000;
    for (let at = 0; at < bytes.length; at += CHUNK) {
      binary += String.fromCharCode(...bytes.subarray(at, at + CHUNK));
    }
    return btoa(binary);
  }

  function reportProblems(problems: string[]) {
    if (problems.length === 0) return;
    toast("warn", "Some of that could not be attached", problems.join("\n"));
  }

  /** Type the paths into the session, the same way typing would. */
  function insertPaths(paths: string[]) {
    const current = project();
    if (!current || paths.length === 0) return;
    // A trailing space so typing carries on after it, and no quoting: this goes into the CLI's
    // input box, not into a shell.
    void api
      .writeToSession(current.id, `${paths.join(" ")} `)
      .catch((error) => toast("error", "Could not type the path", describeError(error)));
  }

  /**
   * Put clipboard files inside the sandbox and type where they went.
   *
   * A pasted image arrives with no path of its own -- the webview hands over bytes and a
   * guess at a name -- so the bytes are copied in through the app, which is the only thing here
   * that talks to Docker. The path typed back is the sandbox's, because that is what the CLI
   * and the agent can read.
   */
  async function attachFiles(files: File[]) {
    const current = project();
    if (!current || attaching()) return;
    setAttaching(true);
    const paths: string[] = [];
    const problems: string[] = [];
    try {
      for (const file of files) {
        const name = file.name || "pasted";
        if (file.size > ATTACH_LIMIT_BYTES) {
          problems.push(
            `${name} is ${Math.round(file.size / (1024 * 1024))} MB; the limit is ${
              ATTACH_LIMIT_BYTES / (1024 * 1024)
            } MB.`,
          );
          continue;
        }
        try {
          const view = await api.attachBytes(current.id, name, await fileToBase64(file));
          paths.push(...view.paths);
          problems.push(...view.problems);
        } catch (error) {
          problems.push(describeError(error));
        }
      }
      insertPaths(paths);
      reportProblems(problems);
    } finally {
      setAttaching(false);
    }
  }

  /** Attach dropped paths: what the sandbox can already see is named, the rest is copied in. */
  async function attachDroppedPaths(paths: string[]) {
    const current = project();
    if (!current || paths.length === 0 || attaching()) return;
    setAttaching(true);
    try {
      const view = await api.attachPaths(current.id, paths);
      insertPaths(view.paths);
      reportProblems(view.problems);
    } catch (error) {
      toast("error", "Could not attach that", describeError(error));
    } finally {
      setAttaching(false);
    }
  }

  return (
    <div class="panel-flush">
      <div class="terminal-wrap" classList={{ "terminal-dropping": dropping() }}>
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
                  {/* Only once the answer is in: this used to fire during the first
                      moments of every launch, when the question had not been asked. */}
                  <Show when={store.info?.docker && !store.info.docker.available}>
                    <div class="callout callout-danger">
                      The Docker daemon is not reachable. Start Docker Desktop, then try again.
                    </div>
                  </Show>
                  <Show
                    when={store.info?.docker?.available && !store.info.docker.image_present}
                  >
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
                  <Show
                    when={!store.building}
                    fallback={
                      <p class="hint">
                        Installing the tools this project asked for. The install is running above,
                        in this terminal, and the project starts by itself as soon as it finishes.
                      </p>
                    }
                  >
                    <button class="btn btn-primary" disabled={busy()} onClick={() => void run()}>
                      {/* A disabled button that says nothing is indistinguishable from a broken
                          one, which is what this looked like while it waited for an answer that
                          never came. */}
                      {busy() ? "Starting…" : "Run project"}
                    </button>
                  </Show>
                </>
              )}
            </Show>
          </div>
        </Show>
      </div>
      <Show when={dropping() || attaching()}>
        <div class="terminal-drop-hint">{attaching() ? "Attaching…" : "Drop to attach"}</div>
      </Show>
      <Show when={project()?.running}>
        <div class="queue-note">
          <span>
            Container <span class="mono">{project()?.containerName}</span> is running. Everything it can see is
            listed under Permissions.
          </span>
          <button class="btn btn-sm" disabled={busy()} onClick={() => void stop()}>
            {busy() ? "Stopping…" : "Stop"}
          </button>
        </div>
      </Show>
    </div>
  );
}
