/**
 * The activity panel: the diagnostics surface.
 *
 * Everything here exists so an operator can answer "why is it doing that?"
 * without reading logs: the exact command that was run, what the sandbox
 * reported, what was refused, the runtime image build output, and the checks
 * that could not be applied on this platform.
 */

import { createSignal, For, Show } from "solid-js";
import * as api from "../lib/api";
import { baseName, formatTimestamp, shortPath } from "../lib/format";
import {
  clearBlockedEgress,
  describeError,
  refreshProjects,
  selectedProject,
  store,
  toast,
} from "../store";

export function ActivityPanel() {
  const project = () => selectedProject();
  const [plan, setPlan] = createSignal<string | null>(null);
  const [planWarnings, setPlanWarnings] = createSignal<string[]>([]);
  const [busy, setBusy] = createSignal(false);
  // Where the app writes what it says about itself, including every error the window showed.
  // Asked for rather than assembled here, so the window does not have its own idea of where
  // that file is.
  const [logPath, setLogPath] = createSignal<string | null>(null);

  async function showPlan() {
    const current = project();
    if (!current) return;
    setBusy(true);
    try {
      const preview = await api.previewPlan(current.id);
      setPlan(preview.text);
      setPlanWarnings(preview.warnings);
    } catch (error) {
      toast("error", "Could not build the plan", describeError(error));
    } finally {
      setBusy(false);
    }
  }

  async function buildImage() {
    setBusy(true);
    try {
      await api.buildRuntimeImage(false);
      toast("info", "Building the runtime image", "Progress appears below.");
    } catch (error) {
      toast("error", "Could not start the build", describeError(error));
    } finally {
      setBusy(false);
    }
  }

  async function cleanup() {
    try {
      const removed = await api.cleanupOrphans();
      toast(
        removed.length > 0 ? "ok" : "info",
        removed.length > 0 ? `Removed ${removed.length} leftover container(s)` : "Nothing to clean up",
        removed.join(", "),
      );
      await refreshProjects();
    } catch (error) {
      toast("error", "Cleanup failed", describeError(error));
    }
  }

  return (
    <div class="panel">
      <Show when={store.startupNotice}>
        {(notice) => (
          <div class="card">
            <div class="callout callout-warn">{notice()}</div>
          </div>
        )}
      </Show>

      <div class="card">
        <h3>What Deepsand runs</h3>
        <p>
          The sandbox is one <span class="mono">docker run</span> command. This is the whole of it — there is no
          second path that starts a container, and nothing in it depends on the sandbox's own good behaviour.
        </p>
        <div class="row-inline" style={{ "margin-top": "0.6rem" }}>
          <button class="btn" disabled={busy() || !project()} onClick={() => void showPlan()}>
            Show the exact command
          </button>
        </div>
        <Show when={planWarnings().length > 0}>
          <div class="callout callout-warn" style={{ "margin-top": "0.7rem" }}>
            {planWarnings().join(" ")}
          </div>
        </Show>
        <Show when={plan()}>
          {(text) => <pre class="output" style={{ "margin-top": "0.7rem" }}>{text()}</pre>}
        </Show>
      </div>

      <div class="card">
        <h3>Runtime image</h3>
        <p>
          The image contains the DeepCode CLI and the sandbox entrypoint. Building it is the only step that needs
          network access on the host.
        </p>
        <div class="row-inline" style={{ "margin-top": "0.6rem" }}>
          <span class="tag">{store.info?.settings.image}</span>
          <Show when={store.info?.docker} fallback={<span class="badge">checking…</span>}>
            {(docker) => (
              <Show
                when={docker().image_present}
                fallback={<span class="badge badge-warn">not built</span>}
              >
                <span class="badge badge-ok">present</span>
              </Show>
            )}
          </Show>
          <button class="btn" disabled={busy() || store.building} onClick={() => void buildImage()}>
            {store.building ? "Building…" : "Build image"}
          </button>
        </div>
        <Show when={store.buildLog.length > 0}>
          <pre class="output" style={{ "margin-top": "0.7rem" }}>{store.buildLog.join("\n")}</pre>
        </Show>
      </div>

      <div class="card">
        <h3>Requests Deepsand discarded</h3>
        <p>
          Requests that arrived on the spool but failed validation. A sandbox can ask for anything, so Deepsand
          checks the shape of what arrives before it reaches your screen.
        </p>
        <Show
          when={store.rejected.length > 0}
          fallback={<div class="empty">Nothing has been discarded.</div>}
        >
          <table>
            <thead>
              <tr>
                <th>File</th>
                <th>Reason</th>
              </tr>
            </thead>
            <tbody>
              <For each={store.rejected}>
                {(entry) => (
                  <tr>
                    <td class="path">{entry.file}</td>
                    <td class="small">{entry.reason}</td>
                  </tr>
                )}
              </For>
            </tbody>
          </table>
        </Show>
      </div>

      <div class="card">
        <h3>Blocked network destinations</h3>
        <p>
          Only applies to allowlisted network mode. Nothing appears here in <span class="mono">internet</span> mode
          because the blocking happens inside the container's kernel, where Deepsand cannot see individual attempts.
          Allowing a host adds it to <strong>this project's</strong> allowlist, not the app-wide one.
        </p>
        <Show
          when={store.blockedEgress.length > 0}
          fallback={<div class="empty">Nothing has been blocked.</div>}
        >
          <table>
            <thead>
              <tr>
                <th>Host</th>
                <th>Port</th>
                <th>Reason</th>
                <th>When</th>
                <th />
              </tr>
            </thead>
            <tbody>
              <For each={store.blockedEgress}>
                {(entry) => (
                  <tr>
                    <td class="path">{entry.host}</td>
                    <td>{entry.port}</td>
                    <td class="small">{entry.reason}</td>
                    <td class="small muted">{formatTimestamp(entry.atMs)}</td>
                    <td>
                      <button
                        class="btn btn-sm"
                        onClick={() => void allowHost(entry.host)}
                        title="Add this host to the egress allowlist"
                      >
                        Allow
                      </button>
                    </td>
                  </tr>
                )}
              </For>
            </tbody>
          </table>
        </Show>
      </div>

      <div class="card">
        <h3>Host and sandbox status</h3>
        <table>
          <tbody>
            <tr>
              <th>Deepsand</th>
              <td>{store.info?.version ?? "?"}</td>
            </tr>
            <tr>
              <th>Data directory</th>
              <td class="path">{store.info?.dataDir ?? "?"}</td>
            </tr>
            <tr>
              <th>Error log</th>
              <td class="path">
                {logPath() ?? "…"}
                <Show when={logPath()}>
                  <button
                    class="btn btn-ghost btn-sm"
                    style={{ "margin-left": "0.4rem" }}
                    title="Copy the log's path"
                    onClick={() => void copyLogPath()}
                  >
                    Copy path
                  </button>
                </Show>
                <div class="small" style={{ "margin-top": "0.2rem" }}>
                  Every error the window shows is written here as well, so it can be read and
                  copied after the box is gone.
                </div>
              </td>
            </tr>
            <tr>
              <th>Docker</th>
              <td>
                <Show
                  when={store.info?.docker}
                  fallback={<span class="badge">checking…</span>}
                >
                  {(docker) => (
                    <>
                      <Show
                        when={docker().available}
                        fallback={<span class="badge badge-danger">daemon not reachable</span>}
                      >
                        <span class="badge badge-ok">server {docker().server_version}</span>
                      </Show>
                      <Show when={docker().desktop}>
                        <span class="badge badge-warn" style={{ "margin-left": "0.4rem" }}>
                          Docker Desktop: limited hardening
                        </span>
                      </Show>
                    </>
                  )}
                </Show>
              </td>
            </tr>
            <tr>
              <th>Model credentials</th>
              <td>
                <Show
                  when={store.info?.hostConfig.apiKey !== "(unset)"}
                  fallback={<span class="badge badge-warn">no API key found</span>}
                >
                  <span class="badge badge-ok">inherited from {baseName(store.info?.hostConfig.path ?? "")}</span>
                </Show>
                <div class="faint small" style={{ "margin-top": "0.3rem" }}>
                  {store.info?.hostConfig.path}
                </div>
              </td>
            </tr>
            <tr>
              <th>Network policy</th>
              <td>
                <Show when={project()} fallback={<span class="muted">no project selected</span>}>
                  {(current) => <span class="tag">{current().network.mode}</span>}
                </Show>
              </td>
            </tr>
          </tbody>
        </table>
        <div class="row-inline" style={{ "margin-top": "0.7rem" }}>
          <button class="btn" onClick={() => void cleanup()}>
            Remove leftover containers
          </button>
          <button class="btn btn-ghost" onClick={() => void reveal()}>
            Show data folder
          </button>
        </div>
      </div>
    </div>
  );

  async function allowHost(host: string) {
    const current = project();
    if (!current) return;
    try {
      // Added to *this project's* list rather than the app-wide one. A host one
      // project happened to need should not silently become reachable from every
      // other project on the machine, which is what the global list would do.
      const view = await api.projectAllowlist(current.id);
      const next = Array.from(new Set([...view.project, host]));
      const updated = await api.setProjectAllowlist(current.id, next);
      toast(
        "ok",
        `Allowed ${host} for ${current.name}`,
        `${updated.effective.length} entr${updated.effective.length === 1 ? "y" : "ies"} in force.`,
      );
      clearBlockedEgress(host);
    } catch (error) {
      toast("error", "Could not update the allowlist", describeError(error));
    }
  }

  async function loadLogPath() {
    try {
      setLogPath(await api.logFilePath());
    } catch {
      /* the row says so, rather than showing a path that may not be right */
    }
  }

  async function copyLogPath() {
    const path = logPath();
    if (!path) return;
    try {
      await navigator.clipboard.writeText(path);
      toast("ok", "Copied", "The log's path is on the clipboard.");
    } catch {
      toast("warn", "Could not copy", path);
    }
  }

  // Asked for once, when the panel is created: the answer cannot change while it is open.
  void loadLogPath();

  async function reveal() {
    try {
      const path = await api.revealDataDir();
      toast("info", "Deepsand's data folder", shortPath(path, 90));
    } catch (error) {
      toast("error", "Could not open the folder", describeError(error));
    }
  }
}
