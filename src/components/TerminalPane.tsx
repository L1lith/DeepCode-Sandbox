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
import { attachTerminal, describeError, restartDocker, selectedProject, sessionOperation, store, toast } from "../store";
import { RestartDockerControl } from "./RestartDocker";

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

    // Ctrl+V is taken over at the keystroke, not only at the paste event.
    //
    // The CLI inside the sandbox binds Ctrl+V to its own paste-a-picture feature, and it sees
    // the keystroke long before any paste event means anything to it -- which is why plain text
    // pasting is what breaks there. Stopping the keystroke here keeps it out of the PTY
    // entirely, and the clipboard is read here instead: text goes in through xterm's own paste,
    // so bracketed paste and the CLI's input box still behave, while an image or a file is
    // copied into the sandbox and its path typed, which is what the CLI can actually read.
    // Counted rather than flagged: two pastes in quick succession are two separate waits.
    let pending = 0;
    const onKeyDown = (event: KeyboardEvent) => {
      const key = event.key.toLowerCase();
      const isPaste =
        ((event.ctrlKey || event.metaKey) && !event.altKey && key === "v") ||
        (event.shiftKey && event.key === "Insert");
      if (!isPaste) return;
      // Stopped, but deliberately not cancelled.
      //
      // Stopping it keeps the keystroke out of the PTY, which is the whole point: the CLI
      // binds Ctrl+V to its own paste-a-picture feature, and that binding is what breaks
      // pasting text. Cancelling it would also cancel the browser's own paste event, and that
      // event is the one route to the clipboard that needs no permission and no prompt -- it
      // carries text, images and files alike. So the keystroke is stopped and the paste event
      // is left to arrive.
      event.stopPropagation();
      pending += 1;
      const ticket = pending;
      window.setTimeout(() => {
        // Only if no paste event turned up. Some payloads -- a bare bitmap with no file behind
        // it, on some builds -- do not come through as an event, and for those the clipboard
        // has to be read directly, which is what asks for the permission. Offering the prompt
        // in that case is right; offering it on every paste was the mistake.
        if (pending === ticket) void pasteClipboard();
      }, 250);
    };
    host.addEventListener("keydown", onKeyDown, true);

    // The paste event itself: the context menu's Paste, and any route the browser handles for
    // us rather than for the key handler. Files are attached; text goes through xterm's paste.
    const onPaste = (event: ClipboardEvent) => {
      // Answered by an event, so the fallback above stays quiet.
      pending += 1;
      const files = Array.from(event.clipboardData?.items ?? [])
        .filter((item) => item.kind === "file")
        .map((item) => item.getAsFile())
        .filter((file): file is File => file !== null);
      if (files.length > 0) {
        event.preventDefault();
        event.stopPropagation();
        void attachFiles(files);
        return;
      }
      // Text too, for the routes that do not go through the key handler: the context menu's
      // Paste, and any keyboard route the webview handles itself. Left unhandled it reaches
      // the CLI's own Ctrl+V binding, which is the thing that breaks it.
      const text = event.clipboardData?.getData("text/plain") ?? "";
      if (!text) return;
      event.preventDefault();
      event.stopPropagation();
      term?.paste(text);
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
        // A drop on this window is a drop on the terminal: there is one terminal pane per
        // window, so the position decides whether the drop hint is lit, never whether the
        // files are taken. Requiring the pointer to land inside the pane meant a drop anywhere
        // else did nothing at all, and said nothing about it.
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
        void attachDroppedPaths(payload.paths);
      })
      .then((unlisten) => {
        unlistenDrop = unlisten;
      })
      .catch(() => {
        /* A platform without drag-and-drop is not a reason to fail to mount. */
      });

    onCleanup(() => {
      window.cancelAnimationFrame(firstFit);
      if (settle !== undefined) window.clearTimeout(settle);
      window.removeEventListener("resize", onWindowResize);
      host.removeEventListener("paste", onPaste, true);
      host.removeEventListener("keydown", onKeyDown, true);
      unlistenDrop?.();
      observer.disconnect();
      dataSub.dispose();
      term?.dispose();
    });
  });

  /**
   * How long a resize has to stop changing before the sandbox is told about it.
   *
   * Dragging a window edge fires the observer for every pixel, and each fit used to send its
   * own resize. Those arrive out of order, so the PTY could be left at the width of some
   * intermediate frame while the pane showed the final one -- and the sandbox then wrapped
   * its output at a column the pane did not have, which is what made the text unreadable
   * after shrinking the window.
   */
  const RESIZE_SETTLE_MS = 120;
  let settle: number | undefined;

  function safeFit() {
    if (!fit || !term || !host) return;
    // A hidden pane has no box, and fitting to zero produces a one-row terminal that
    // then has to be corrected. Doing nothing is correct: the resize observer fires
    // when the pane is shown again.
    if (host.clientWidth === 0 || host.clientHeight === 0) return;
    try {
      // Fitting straight away keeps the pane's own wrapping matched to its box while the
      // drag is happening; only the size the sandbox hears about waits for the drag to stop.
      fit.fit();
    } catch {
      /* the pane can be zero-sized during layout; nothing to do */
    }
    if (settle !== undefined) window.clearTimeout(settle);
    settle = window.setTimeout(() => {
      settle = undefined;
      if (!fit || !term || !host) return;
      if (host.clientWidth === 0 || host.clientHeight === 0) return;
      try {
        fit.fit();
        // Painting the whole viewport again clears the half-wrapped lines a shrink leaves
        // behind: xterm keeps them until something asks it to draw that part of the buffer.
        term.refresh(0, Math.max(0, term.rows - 1));
        const current = project();
        if (current) {
          void api.resizeSession(current.id, term.rows, term.cols).catch(() => undefined);
        }
      } catch {
        /* the pane can be zero-sized during layout; nothing to do */
      }
    }, RESIZE_SETTLE_MS);
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

  /**
   * Start now, with the tools built behind the session rather than in front of it.
   *
   * The same shape as `run`, deliberately: the button state, the toast and the fit all have to
   * behave the same way, and a second path that skipped one of them is how a button ends up
   * looking broken.
   */
  async function runWithoutTools() {
    const current = project();
    if (!current) return;
    await sessionOperation(current.id, async () => {
      try {
        await api.startSessionWithoutTools(current.id);
        toast("ok", `Starting ${current.name}`, "Installing the tools in the background.");
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

  /**
   * Restart Docker's engine — including the WSL2 distro it runs in — and start the project
   * again.
   *
   * The last resort for a wedged runtime, and the reason it is worth a button: `docker create`
   * and `docker cp` keep answering while `docker start` hangs, so nothing done to the
   * *containers* can help; only restarting the engine can. That ends every container on this
   * machine, so it happens only after the operator confirms, and it re-runs the launch they
   * were trying to do rather than leaving them to press Run again.
   */
  async function restartDockerAndRetry() {
    const current = project();
    if (!current) return;
    await sessionOperation(current.id, async () => {
      try {
        await restartDocker();
        await api.startSession(current.id, true);
        toast("ok", `Restarted Docker and started ${current.name}`);
        window.setTimeout(() => safeFit(), 120);
      } catch (error) {
        toast("error", "Could not restart Docker", describeError(error));
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
   * Read the clipboard and put it into the session.
   *
   * Text is handed to xterm's paste rather than written straight to the session, so it is
   * wrapped in the bracketed-paste markers the CLI asked for and arrives as one paste rather
   * than as typing. A screenshot arrives as bytes with no path at all, so it becomes a file
   * named for its type, is copied into the sandbox, and its sandbox path is typed.
   */
  async function pasteClipboard() {
    const current = project();
    if (!current) return;
    try {
      const items = await navigator.clipboard.read();
      const files: File[] = [];
      let text = "";
      for (const item of items) {
        const imageType = item.types.find((type) => type.startsWith("image/"));
        if (imageType) {
          const blob = await item.getType(imageType);
          const extension = imageType.split("/")[1] || "png";
          files.push(new File([blob], `pasted-image.${extension}`, { type: imageType }));
          continue;
        }
        if (item.types.includes("text/plain")) {
          text += await (await item.getType("text/plain")).text();
        }
      }
      if (files.length > 0) {
        await attachFiles(files);
        return;
      }
      if (text) {
        term?.paste(text);
        return;
      }
      toast(
        "warn",
        "Nothing to paste",
        "The clipboard is empty, or holds something the terminal cannot take.",
      );
    } catch (error) {
      console.warn("the clipboard could not be read", error);
      // A refusal is a question the operator has to answer, not a fault: saying "could not
      // paste" for it left them with nothing to act on when the answer was one click away.
      const refused =
        error instanceof DOMException &&
        (error.name === "NotAllowedError" || error.name === "SecurityError");
      if (refused) {
        toast(
          "warn",
          "Deepsand needs permission to read the clipboard",
          "Windows asked once and the answer was no, so this paste had nothing to work " +
            "with. Allow it, then paste again; from then on Ctrl+V goes straight in.",
        );
        return;
      }
      toast(
        "warn",
        "Could not read the clipboard",
        "Use right-click then Paste in the terminal instead.",
      );
    }
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
                      <p>
                        {store.info?.docker?.detail ||
                          "The Docker daemon is not reachable. Start Docker Desktop, then try again."}
                      </p>
                      {/* Only Docker Desktop can be restarted this way. The daemon being
                          wedged is one of the two states this shows, and `docker create`
                          answering while `docker start` hangs is precisely the one a
                          container-only fix cannot reach. */}
                      <Show
                        when={store.info?.docker?.desktop}
                        fallback={<p class="hint">Start the Docker daemon, then try again.</p>}
                      >
                        <RestartDockerControl
                          busy={busy()}
                          confirmLabel="Restart Docker Desktop and retry"
                          onConfirm={() => void restartDockerAndRetry()}
                        />
                      </Show>
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
                    <button
                      class="btn"
                      disabled={busy()}
                      title="Start now on an image with no tools, and copy the built ones in when they are ready. A tool installed as a system package still needs a restart."
                      onClick={() => void runWithoutTools()}
                    >
                      Start without tools
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
