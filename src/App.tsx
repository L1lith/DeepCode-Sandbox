/**
 * The application shell.
 *
 * Layout: a project sidebar, a header with the sandbox controls, and three tabs
 * (terminal, permissions, activity). Permission requests are surfaced as a modal
 * regardless of which tab is open, because they are time-boxed by the model's
 * own tool-call timeout.
 */

import { createMemo, createSignal, For, onCleanup, onMount, Show } from "solid-js";
import * as api from "./lib/api";
import { baseName } from "./lib/format";
import { networkLabel } from "./lib/types";
import {
  bootstrap,
  cancelBuild,
  describeError,
  refreshProjectData,
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
import {
  NewProjectDialog,
  PermissionDialog,
  ProjectSettingsDialog,
  SettingsDialog,
  Toasts,
} from "./components/Dialogs";

type Tab = "terminal" | "permissions" | "tools" | "secrets" | "activity";

export default function App() {
  const [tab, setTab] = createSignal<Tab>("terminal");
  const [showNewProject, setShowNewProject] = createSignal(false);
  const [showSettings, setShowSettings] = createSignal(false);
  const [showProjectSettings, setShowProjectSettings] = createSignal(false);

  const project = () => selectedProject();
  // The same state the terminal's button reads, so the two cannot disagree about whether a
  // run is in flight -- which they did, and that is why one of them could be left greyed out.
  const busy = () => store.sessionBusy === project()?.id;

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
    onCleanup(() => dispose?.());
  });

  async function run() {
    const current = project();
    if (!current) return;
    await sessionOperation(current.id, async () => {
      try {
        await api.startSession(current.id, true);
        toast("ok", `Started ${current.name}`);
        setTab("terminal");
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

  return (
    <Show
      when={store.ready}
      fallback={
        <div class="empty" style={{ "margin-top": "40vh" }}>
          Starting Deepsand…
        </div>
      }
    >
      <div class="shell">
        {/* ------------------------------------------------------------ */}
        <aside class="sidebar">
          <div class="sidebar-head">
            <div class="brand">
              <h1>Deepsand</h1>
              <span>v{store.info?.version ?? "?"}</span>
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
                    aria-current={entry.id === store.selectedId}
                    onClick={() => void pick(entry.id)}
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
              <div class="empty" style={{ "margin-top": "30vh" }}>
                <h3>No project selected</h3>
                <p class="muted">
                  Create a project, give it a working directory, and run DeepCode inside a container that can only
                  see that directory.
                </p>
              </div>
            }
          >
            {(current) => (
              <>
                <header class="header">
                  <div class="header-top">
                    <h2>{current().name}</h2>
                    <span class={current().running ? "badge badge-ok" : "badge"}>
                      <span class="dot" />
                      {current().running ? "running" : "stopped"}
                    </span>
                    <span class="badge badge-accent" title={networkLabel(current().network)}>
                      {networkLabel(current().network)}
                    </span>
                    <span class="badge">{current().grantCount} shared</span>
                    <Show when={store.requests.length > 0}>
                      <span class="badge badge-danger">
                        {store.requests.length} permission request
                        {store.requests.length === 1 ? "" : "s"}
                      </span>
                    </Show>
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

      <Toasts />
    </Show>
  );
}
