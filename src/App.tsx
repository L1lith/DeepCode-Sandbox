/**
 * The application shell.
 *
 * Layout: a project sidebar, a header with the sandbox controls, and three tabs
 * (terminal, permissions, activity). Permission requests are surfaced as a modal
 * regardless of which tab is open, because they are time-boxed by the model's
 * own tool-call timeout.
 */

import { createEffect, createMemo, createSignal, For, on, onCleanup, onMount, Show } from "solid-js";
import * as api from "./lib/api";
import { baseName, formatBytes } from "./lib/format";
import { networkLabel, type ProjectDiskUsage } from "./lib/types";
import {
  bootstrap,
  cancelBuild,
  describeError,
  moveProject,
  refreshProjectData,
  restartDocker,
  revealProjectDir,
  selectProject,
  selectedProject,
  sessionOperation,
  store,
  toast,
  wireEvents,
} from "./store";
import { ActivityPanel } from "./components/ActivityPanel";
import { EffortSwitch, ModelSelect, ToolsPanel } from "./components/ToolsPanel";
import { SecretsPanel } from "./components/SecretsPanel";
import { BuildProgress } from "./components/BuildProgress";
import { PermissionsPanel } from "./components/PermissionsPanel";
import { TerminalPane } from "./components/TerminalPane";
import { RestartDockerControl } from "./components/RestartDocker";
import {
  NewProjectDialog,
  PermissionDialog,
  ProjectSettingsDialog,
  SettingsDialog,
  Toasts,
} from "./components/Dialogs";

type Tab = "terminal" | "permissions" | "tools" | "secrets" | "activity";

/**
 * The sidebar's hidden state, remembered per window.
 *
 * A UI preference rather than a project setting: it belongs to this window, and putting it in
 * the state file would make every launch wait on the backend to know where to put the sidebar.
 * Storage can be denied; the answer is then simply "shown".
 */
const SIDEBAR_HIDDEN_KEY = "deepsand.sidebar.hidden";

function sidebarStartsHidden(): boolean {
  try {
    return window.localStorage.getItem(SIDEBAR_HIDDEN_KEY) === "1";
  } catch {
    return false;
  }
}

/**
 * The one sidebar control, in the two places it is needed.
 *
 * In the project header it is a flex item beside the title, so the two share a line and a
 * vertical centre and neither can drift when the header wraps. With no project there is no
 * header, so it floats in the same corner of the main area instead.
 */
function SidebarToggle(props: { hidden: boolean; floating?: boolean; onToggle: () => void }) {
  return (
    <button
      class="btn btn-ghost btn-sm sidebar-toggle"
      classList={{ "sidebar-toggle-floating": props.floating }}
      aria-label={props.hidden ? "Show project sidebar" : "Hide project sidebar"}
      aria-expanded={!props.hidden}
      aria-controls="project-sidebar"
      title={props.hidden ? "Show the project sidebar" : "Hide the project sidebar"}
      onClick={props.onToggle}
    >
      <span aria-hidden="true">☰</span>
    </button>
  );
}

export default function App() {
  const [tab, setTab] = createSignal<Tab>("terminal");
  const [showNewProject, setShowNewProject] = createSignal(false);
  const [showSettings, setShowSettings] = createSignal(false);
  const [showProjectSettings, setShowProjectSettings] = createSignal(false);
  /** The project being dragged, and the row it is over, so the drop shows before it lands. */
  const [dragId, setDragId] = createSignal<string | null>(null);
  /** The row under the pointer, and which side the dragged project would land on it. */
  const [over, setOver] = createSignal<{ id: string; below: boolean } | null>(null);
  /** The right-click menu: which project it is about, and where the pointer opened it. */
  const [menu, setMenu] = createSignal<{ projectId: string; x: number; y: number } | null>(null);
  /** Whether the project sidebar is slid out of the way. */
  const [sidebarHidden, setSidebarHidden] = createSignal(sidebarStartsHidden());

  function toggleSidebar() {
    const hidden = !sidebarHidden();
    setSidebarHidden(hidden);
    try {
      window.localStorage.setItem(SIDEBAR_HIDDEN_KEY, hidden ? "1" : "0");
    } catch {
      // The preference still applies to this session; it just will not be remembered.
    }
  }

  const project = () => selectedProject();
  // The same state the terminal's button reads, so the two cannot disagree about whether a
  // run is in flight -- which they did, and that is why one of them could be left greyed out.
  const busy = () => store.sessionBusy === project()?.id;

  /**
   * The selected project's folder size.
   *
   * `undefined` means a walk is in flight, `null` means there is nothing honest to show, and
   * the object is the answer. It is not part of `ProjectView`: that list is refreshed often,
   * and walking every project on every refresh would be absurd.
   */
  const [disk, setDisk] = createSignal<ProjectDiskUsage | null | undefined>(undefined);

  // Re-measure when the selection changes, and when the sandbox starts or stops -- the moments
  // a build or a cleanup is most likely to have changed the folder. A string dependency means a
  // routine project-list refresh does not re-walk it.
  createEffect(
    on(
      () => `${project()?.id ?? ""}:${project()?.running ? "running" : "stopped"}`,
      () => {
        const current = project();
        if (!current || !current.workspaceExists) {
          setDisk(null);
          return;
        }
        setDisk(undefined);
        const measuredFor = current.id;
        void api
          .projectDiskUsage(measuredFor)
          .then((usage) => {
            // The operator may have switched projects while the walk was running; a late answer
            // for the old one must not replace the new one's number.
            if (project()?.id === measuredFor) setDisk(usage);
          })
          .catch(() => {
            // Not a reason to break the header; the command already logged the failure.
            if (project()?.id === measuredFor) setDisk(null);
          });
      },
    ),
  );

  /** What the disk badge says; empty when there is nothing honest to show. */
  const diskLabel = () => {
    const usage = disk();
    if (usage === undefined) return "measuring disk…";
    if (usage === null) return "";
    return `${usage.complete ? "" : "≥ "}${formatBytes(usage.bytes)} on disk`;
  };

  const diskTitle = () => {
    const usage = disk();
    if (usage === undefined) return "Measuring this project's folder…";
    if (usage && !usage.complete) {
      return "Some files could not be read, so this is a lower bound on the project folder's size. Build output such as target/ and node_modules/ is included; a physical file with more than one hard link is counted once.";
    }
    return "Total size of this project's folder on disk, including build output such as target/ and node_modules/. A physical file with more than one hard link is counted once.";
  };

  /**
   * A Docker restart started from the status strip.
   *
   * Local rather than `sessionBusy`, because this is not a project's session -- the strip is
   * global. No launch is retried from here either: starting a project nobody asked to start
   * would be a surprise, and the project pane's own control is where a refused launch is
   * retried.
   */
  const [dockerBusy, setDockerBusy] = createSignal(false);

  async function restartDockerFromStatus() {
    if (dockerBusy()) return;
    setDockerBusy(true);
    try {
      await restartDocker();
      toast("ok", "Docker is back");
    } catch (error) {
      toast("error", "Could not restart Docker", describeError(error));
    } finally {
      setDockerBusy(false);
    }
  }

  // The oldest outstanding request is the one on screen; the rest queue behind.
  const activeRequest = createMemo(() => {
    const sorted = [...store.requests].sort((a, b) => a.surfacedAtMs - b.surfacedAtMs);
    return sorted[0];
  });

  onMount(() => {
    void bootstrap();
    let dispose: (() => void) | undefined;
    void wireEvents().then((fn) => {
      dispose = fn;
    });
    // Escape closes the project menu, the same key that dismisses everything else. A click
    // anywhere closes it too; see the backdrop.
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") setMenu(null);
    };
    window.addEventListener("keydown", onKey);
    onCleanup(() => {
      dispose?.();
      window.removeEventListener("keydown", onKey);
    });
  });

  async function run() {
    const current = project();
    if (!current) return;
    await sessionOperation(current.id, async () => {
      try {
        const status = await api.startSession(current.id, true);
        // A start waiting for a build returns the current status when a newer start
        // supersedes it; it did not start a sandbox, so it must not say that it did.
        if (status.running) {
          toast("ok", `Started ${current.name}`);
          setTab("terminal");
        }
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

  async function restart() {
    const current = project();
    if (!current) return;
    await sessionOperation(current.id, async () => {
      try {
        await api.restartSession(current.id);
        toast("ok", "Sandbox restarted", "The session resumed where it left off.");
      } catch (error) {
        toast("error", "Could not restart the sandbox", describeError(error));
      }
    });
  }

  async function pick(projectId: string) {
    await selectProject(projectId);
    await refreshProjectData(projectId);
  }

  /**
   * When the last drag ended. The click that follows a drag is not a selection, and a timestamp
   * rather than a flag means a click that never arrives cannot swallow a later, real one.
   */
  let dragEndedAt = 0;
  /** The rows we drew, by project id, so a drag can ask which one a point is over. */
  const rowElements = new Map<string, HTMLElement>();

  /**
   * The index, in the list as it will be *after* the dragged row is lifted out, that puts it
   * where the pointer was released.
   */
  function landingIndex(dragged: string, target: string, below: boolean): number | null {
    const ids = store.projects.map((entry) => entry.id);
    const from = ids.indexOf(dragged);
    const to = ids.indexOf(target);
    if (from < 0 || to < 0 || from === to) return null;
    // `below` means "after the row it is over", and that is a different index depending on
    // which side the dragged row started on, because it is lifted out before it is put back.
    if (below) return from < to ? to : to + 1;
    return from < to ? to - 1 : to;
  }

  /**
   * Start dragging a project row, and follow the pointer until it is released.
   *
   * Pointer events rather than HTML5 drag-and-drop, and that is not a style choice: the window
   * has Tauri's own drag-and-drop turned on, which is what lets a file be dropped onto the
   * terminal -- and on Windows that is the same channel the webview needs in order to deliver
   * `dragstart`, so those events never arrive and a row simply would not drag. Pointer events
   * are delivered either way, so the reorder works and the file drop keeps working.
   */
  function beginDrag(event: PointerEvent, projectId: string) {
    // Primary button only; the secondary one opens the context menu.
    if (event.button !== 0) return;
    const target = event.currentTarget as HTMLElement;
    const startX = event.clientX;
    const startY = event.clientY;
    const pointerId = event.pointerId;
    let moved = false;

    /** The row under a point, and which half of it the point is in. */
    function rowAt(x: number, y: number): { id: string; below: boolean } | null {
      for (const [id, element] of rowElements) {
        if (!element.isConnected) {
          rowElements.delete(id);
          continue;
        }
        const box = element.getBoundingClientRect();
        if (x >= box.left && x <= box.right && y >= box.top && y <= box.bottom) {
          return { id, below: y > box.top + box.height / 2 };
        }
      }
      return null;
    }

    function detach() {
      window.removeEventListener("pointermove", onMove);
      window.removeEventListener("pointerup", onUp);
      window.removeEventListener("pointercancel", onCancel);
    }

    function onMove(move: PointerEvent) {
      if (!moved) {
        // A few pixels of slack, so a click with a shaky hand is still a click.
        if (Math.abs(move.clientX - startX) < 4 && Math.abs(move.clientY - startY) < 4) return;
        moved = true;
        setDragId(projectId);
      }
      const row = rowAt(move.clientX, move.clientY);
      setOver(row && row.id !== projectId ? row : null);
    }

    function onUp(up: PointerEvent) {
      detach();
      setDragId(null);
      setOver(null);
      if (!moved) return;
      // Recorded here rather than when the threshold was crossed, so it marks the end of the
      // gesture the click handler will see.
      dragEndedAt = performance.now();
      const row = rowAt(up.clientX, up.clientY);
      if (!row || row.id === projectId) return;
      const landing = landingIndex(projectId, row.id, row.below);
      if (landing !== null) void moveProject(projectId, landing);
    }

    function onCancel() {
      detach();
      setDragId(null);
      setOver(null);
    }

    window.addEventListener("pointermove", onMove);
    window.addEventListener("pointerup", onUp);
    window.addEventListener("pointercancel", onCancel);
    // So the moves keep coming once the pointer has left the row it started on.
    try {
      target.setPointerCapture(pointerId);
    } catch {
      /* the window listeners above are what actually track the drag */
    }
  }

  function openRoot(projectId: string) {
    setMenu(null);
    void revealProjectDir(projectId);
  }

  return (
    <Show
      when={store.ready}
      fallback={
        <div class="empty" style={{ "margin-top": "40vh" }}>
          Starting Deepsand…
        </div>
      }
    >
      <div class="shell" classList={{ "sidebar-hidden": sidebarHidden() }}>
        {/* ------------------------------------------------------------ */}
        <aside class="sidebar" id="project-sidebar">
          <div class="sidebar-head">
            <div class="brand">
              <h1>Deepsand</h1>
              <span>v{store.info?.version ?? "?"}</span>
              {/* Which kind of build this is, beside the version, so a screenshot carries it too.
                  A local build shares one data directory with the installed app, and nothing else
                  on screen tells the two apart. */}
              <Show when={store.info?.dev}>
                <span class="dev-badge" title="A local build, not a released one">
                  dev mode
                </span>
              </Show>
            </div>
            <p class="brand-tagline">
              DeepCode runs inside a container that can only see the project you choose.
            </p>
            <button class="btn btn-primary" style={{ width: "100%" }} onClick={() => setShowNewProject(true)}>
              New project
            </button>
          </div>

          <div class="project-list">
            <Show
              when={store.projects.length > 0}
              fallback={
                <div class="empty">
                  No projects yet.
                  <br />
                  Create one to get a sandbox.
                </div>
              }
            >
              <For each={store.projects}>
                {(entry) => (
                  <button
                    class="project-item"
                    classList={{
                      dragging: dragId() === entry.id,
                      "drop-above": over()?.id === entry.id && over()?.below === false,
                      "drop-below": over()?.id === entry.id && over()?.below === true,
                    }}
                    ref={(element: HTMLButtonElement) => {
                      rowElements.set(entry.id, element);
                    }}
                    aria-current={entry.id === store.selectedId}
                    onClick={() => {
                      // The pointer sequence that ends a drag can still end in a click, and that
                      // click is not a selection of the row that was just moved.
                      if (performance.now() - dragEndedAt < 250) return;
                      void pick(entry.id);
                    }}
                    onPointerDown={(event) => beginDrag(event, entry.id)}
                    onContextMenu={(event) => {
                      event.preventDefault();
                      // Clamped to the window, so right-clicking the bottom row does not open
                      // the menu off the edge of the screen.
                      setMenu({
                        projectId: entry.id,
                        x: Math.min(event.clientX, window.innerWidth - 200),
                        y: Math.min(event.clientY, window.innerHeight - 52),
                      });
                    }}
                  >
                    <div class="row">
                      <span class="name">{entry.name}</span>
                      <Show when={entry.running}>
                        <span class="badge badge-ok">
                          <span class="dot" /> running
                        </span>
                      </Show>
                      <Show when={entry.pendingRequests > 0}>
                        <span class="badge badge-danger">{entry.pendingRequests} asking</span>
                      </Show>
                      {/* Held while a dialog is open: the sandbox is frozen, so "running" would
                          otherwise be the only thing this row said about it. */}
                      <Show when={entry.paused}>
                        <span class="badge badge-warn">
                          <span class="dot" /> held
                        </span>
                      </Show>
                    </div>
                    <div class="path" title={entry.rootDir}>
                      {baseName(entry.rootDir)}
                    </div>
                  </button>
                )}
              </For>
            </Show>
          </div>

          <div class="sidebar-foot">
            <Show
              when={store.info?.docker}
              fallback={
                <span class="badge">
                  <span class="dot" /> Checking Docker…
                </span>
              }
            >
              {(docker) => (
                <Show
                  when={docker().available}
                  fallback={
                    <>
                      <span class="badge badge-danger">
                        <span class="dot" /> Docker daemon unreachable
                      </span>
                      <span class="faint">{docker().detail}</span>
                      {/* Only Docker Desktop can be restarted this way; a bare daemon is the
                          business of whatever supervises it. Nothing is retried from here --
                          see `restartDockerFromStatus`. */}
                      <Show when={docker().desktop}>
                        <RestartDockerControl
                          compact
                          busy={dockerBusy()}
                          onConfirm={() => void restartDockerFromStatus()}
                        />
                      </Show>
                    </>
                  }
                >
                  <div class="row-inline">
                    <span class="badge badge-ok">
                      <span class="dot" /> Docker {docker().server_version}
                    </span>
                    <Show when={!docker().image_present}>
                      <span class="badge badge-warn">image missing</span>
                    </Show>
                  </div>
                </Show>
              )}
            </Show>
            <button class="btn btn-ghost btn-sm" onClick={() => setShowSettings(true)}>
              Settings
            </button>
          </div>
        </aside>

        {/* ------------------------------------------------------------ */}
        <main class="main">
          <Show
            when={project()}
            fallback={
              <>
                <SidebarToggle
                  floating
                  hidden={sidebarHidden()}
                  onToggle={toggleSidebar}
                />
                <div class="empty" style={{ "margin-top": "30vh" }}>
                  <h3>No project selected</h3>
                  <p class="muted">
                    Create a project, give it a working directory, and run DeepCode inside a container that can only
                    see that directory.
                  </p>
                </div>
              </>
            }
          >
            {(current) => (
              <>
                <header class="header">
                  <div class="header-top">
                    {/* A flex sibling of the title, so the two are centred on the same line
                        and stay that way when the header wraps at a different width. */}
                    <SidebarToggle hidden={sidebarHidden()} onToggle={toggleSidebar} />
                    <h2>{current().name}</h2>
                    <span class={current().running ? "badge badge-ok" : "badge"}>
                      <span class="dot" />
                      {current().running ? "running" : "stopped"}
                    </span>
                    <span class="badge badge-accent" title={networkLabel(current().network)}>
                      {networkLabel(current().network)}
                    </span>
                    <span class="badge">{current().grantCount} shared</span>
                    {/* The folder's real size, not a guess from the project list: it is
                        measured when the selection changes and when the sandbox stops or
                        starts, which is when a build or a cleanup has changed it. */}
                    <Show when={diskLabel()}>
                      <span class="badge badge-disk" title={diskTitle()}>
                        {diskLabel()}
                      </span>
                    </Show>
                    <Show when={store.requests.length > 0}>
                      <span class="badge badge-danger">
                        {store.requests.length} permission request
                        {store.requests.length === 1 ? "" : "s"}
                      </span>
                    </Show>
                  </div>
                  {/* Its own row rather than a flex item that shares the title's line. At the
                      wider width the whole block used to fit beside the title, and because it
                      wraps internally it made that line 74px tall -- which centred the 32px
                      title halfway down it. A separate row keeps the first line exactly one
                      title high in both sidebar states. */}
                  <div class="header-actions">
                    {/* While tools are being installed there is no session to stop, but there
                        is a build to stop, and this is where an operator looks for it. */}
                    <Show when={store.building}>
                      <button class="btn" onClick={() => void cancelBuild()}>
                        Stop build
                      </button>
                    </Show>
                    {/* The model comes before the thinking intensity: it decides what is
                        doing the thinking. */}
                    <ModelSelect />
                    <EffortSwitch />
                    <Show
                      when={current().running}
                      fallback={
                        <button class="btn btn-primary" disabled={busy()} onClick={() => void run()}>
                          {busy() ? "Starting…" : "Run"}
                        </button>
                      }
                    >
                      <button class="btn" disabled={busy()} onClick={() => void restart()}>
                        Restart
                      </button>
                      <button class="btn" disabled={busy()} onClick={() => void stop()}>
                        Stop
                      </button>
                    </Show>
                    <button class="btn btn-ghost" onClick={() => setShowProjectSettings(true)}>
                      Project settings
                    </button>
                  </div>
                  <div class="header-sub" title={current().rootDir}>
                    {current().rootDir} → /workspace
                  </div>
                </header>

                {/* Above the tabs rather than inside one: a first Run builds the
                    image before the sandbox exists, so this is visible whichever tab
                    the operator happens to be on. */}
                <BuildProgress />

                <nav class="tabs">
                  <button
                    class="tab"
                    aria-selected={tab() === "terminal"}
                    onClick={() => setTab("terminal")}
                  >
                    Terminal
                  </button>
                  <button
                    class="tab"
                    aria-selected={tab() === "permissions"}
                    onClick={() => setTab("permissions")}
                  >
                    Permissions
                    <Show when={current().grantCount > 0}>
                      <span class="tab-badge">{current().grantCount}</span>
                    </Show>
                  </button>
                  <button class="tab" aria-selected={tab() === "tools"} onClick={() => setTab("tools")}>
                    Tools
                  </button>
                  <button
                    class="tab"
                    aria-selected={tab() === "secrets"}
                    onClick={() => setTab("secrets")}
                  >
                    Secrets
                  </button>
                  <button class="tab" aria-selected={tab() === "activity"} onClick={() => setTab("activity")}>
                    Activity
                    <Show when={store.requests.length > 0}>
                      <span class="count">{store.requests.length}</span>
                    </Show>
                  </button>
                </nav>

                {/* The terminal stays mounted while another tab is showing, and is
                    hidden rather than unmounted. Recreating it per tab switch threw away
                    the scrollback and re-measured the pane mid-layout, which is what made
                    the terminal refuse to scroll until something resized it. Hidden, the
                    buffer survives and the pane re-fits when it is shown again. */}
                <div class="tab-host" classList={{ "tab-host-hidden": tab() !== "terminal" }}>
                  <TerminalPane />
                </div>
                <Show when={tab() === "tools"}>
                  <ToolsPanel />
                </Show>
                <Show when={tab() === "secrets"}>
                  <SecretsPanel />
                </Show>
                <Show when={tab() === "permissions"}>
                  <PermissionsPanel />
                </Show>
                <Show when={tab() === "activity"}>
                  <ActivityPanel />
                </Show>
              </>
            )}
          </Show>
        </main>
      </div>

      {/* -------------------------------------------------------------- */}
      <Show when={activeRequest()}>
        {(request) => (
          <PermissionDialog request={request()} queued={store.requests.length} />
        )}
      </Show>

      <Show when={showNewProject()}>
        <NewProjectDialog onClose={() => setShowNewProject(false)} />
      </Show>

      <Show when={showSettings() && store.settings}>
        <SettingsDialog settings={store.settings!} onClose={() => setShowSettings(false)} />
      </Show>

      <Show when={showProjectSettings() && project()}>
        <ProjectSettingsDialog project={project()!} onClose={() => setShowProjectSettings(false)} />
      </Show>

      <Show when={store.fatal}>
        {(message) => (
          <div class="scrim">
            <div class="modal">
              <div class="modal-head">
                <h2>Deepsand could not start</h2>
              </div>
              <div class="modal-body">
                <pre class="output">{message()}</pre>
              </div>
            </div>
          </div>
        )}
      </Show>

      {/* The project right-click menu. The full-window backdrop behind it is what dismisses it
          on the next click anywhere -- including a right-click -- without a document listener
          that has to be torn down. */}
      <Show when={menu()}>
        {(open) => (
          <>
            <div
              class="context-backdrop"
              onClick={() => setMenu(null)}
              onContextMenu={(event) => {
                event.preventDefault();
                setMenu(null);
              }}
            />
            <div class="context-menu" style={{ left: `${open().x}px`, top: `${open().y}px` }}>
              <button class="context-item" onClick={() => openRoot(open().projectId)}>
                Open root directory
              </button>
            </div>
          </>
        )}
      </Show>

      <Toasts />
    </Show>
  );
}
