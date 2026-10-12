/**
 * The permissions panel: everything the sandbox can currently reach, plus the
 * audit trail of every decision.
 *
 * This is the authoritative view. If a directory is not in this table, the
 * sandbox cannot see it — not through a path, not through a symlink, not
 * through the network — because it is not mounted.
 */

import { createEffect, createSignal, For, onMount, Show } from "solid-js";
import { open } from "@tauri-apps/plugin-dialog";
import * as api from "../lib/api";
import {
  accessLabel,
  networkDescription,
  networkLabel,
  type AllowlistView,
  type NetworkPolicy,
} from "../lib/types";
import {
  describeError,
  refreshProjects,
  refreshProjectData,
  selectedProject,
  store,
  toast,
} from "../store";

export function PermissionsPanel() {
  const project = () => selectedProject();

  // Reload whenever the selected project changes, so switching projects never
  // shows the previous project's entries.
  createEffect(() => {
    const current = selectedProject();
    if (current) void loadAllowlist(current.id);
    else setAllowlist(null);
  });

  const [draftPath, setDraftPath] = createSignal("");
  const [draftAccess, setDraftAccess] = createSignal<"read" | "write">("read");
  const [draftPurpose, setDraftPurpose] = createSignal("");
  const [checkNote, setCheckNote] = createSignal<{ ok: boolean; text: string } | null>(null);
  const [busy, setBusy] = createSignal(false);

  // Network access lives here rather than in Project settings, because this tab is
  // already the answer to "what can this project reach".
  const [allowlist, setAllowlist] = createSignal<AllowlistView | null>(null);
  const [allowlistDraft, setAllowlistDraft] = createSignal("");
  const [allowlistBusy, setAllowlistBusy] = createSignal(false);
  const [presets, setPresets] = createSignal<{ name: string; entries: string[] }[]>([]);
  const [modeBusy, setModeBusy] = createSignal(false);

  onMount(() => {
    void api
      .networkPresets()
      .then(setPresets)
      .catch(() => setPresets([]));
  });

  async function loadAllowlist(projectId: string) {
    try {
      const view = await api.projectAllowlist(projectId);
      setAllowlist(view);
      setAllowlistDraft(view.project.join("\n"));
    } catch (error) {
      toast("error", "Could not read this project's allowlist", describeError(error));
    }
  }

  async function saveAllowlist() {
    const current = project();
    if (!current) return;
    setAllowlistBusy(true);
    try {
      const entries = allowlistDraft()
        .split("\n")
        .map((line) => line.trim())
        .filter(Boolean);
      const view = await api.setProjectAllowlist(current.id, entries);
      setAllowlist(view);
      setAllowlistDraft(view.project.join("\n"));
      toast(
        "ok",
        "Allowlist saved",
        `${view.effective.length} entr${view.effective.length === 1 ? "y" : "ies"} in force for this project.`,
      );
    } catch (error) {
      toast("error", "Could not save the allowlist", describeError(error));
    } finally {
      setAllowlistBusy(false);
    }
  }

  async function chooseMode(next: string) {
    const current = project();
    if (!current) return;
    setModeBusy(true);
    try {
      // Switching into restricted mode keeps whatever this project already listed,
      // and starts from an empty project list otherwise: the global list is
      // inherited automatically, so copying it in here would show the same entries
      // twice and make them look project-specific when they are not.
      const policy: NetworkPolicy =
        next === "restricted"
          ? { mode: "restricted", allow: allowlist()?.project ?? [] }
          : ({ mode: next } as NetworkPolicy);
      await api.updateProjectSettings({ projectId: current.id, network: policy });
      await refreshProjects();
      await loadAllowlist(current.id);
      toast("info", "Network mode changed", "Restart the sandbox for it to take effect.");
    } catch (error) {
      toast("error", "Could not change the network mode", describeError(error));
    } finally {
      setModeBusy(false);
    }
  }

  async function browse() {
    const chosen = await open({
      directory: true,
      multiple: false,
      title: "Choose a directory to share with this sandbox",
    });
    if (typeof chosen === "string") {
      setDraftPath(chosen);
      await check(chosen);
    }
  }

  async function check(path: string) {
    if (!path.trim()) {
      setCheckNote(null);
      return;
    }
    try {
      const result = await api.pathCheck(path);
      setCheckNote(
        result.allowed
          ? { ok: true, text: `Allowed. It would appear as a mount inside the sandbox.` }
          : { ok: false, text: result.reason ?? "This path cannot be shared." },
      );
    } catch (error) {
      setCheckNote({ ok: false, text: describeError(error) });
    }
  }

  async function add() {
    const current = project();
    if (!current) return;
    setBusy(true);
    try {
      await api.addGrant(current.id, draftPath(), draftAccess(), undefined, draftPurpose());
      toast("ok", "Permission added", "Restart the sandbox to attach it.");
      setDraftPath("");
      setDraftPurpose("");
      setCheckNote(null);
      await refreshProjectData(current.id);
    } catch (error) {
      toast("error", "Could not add that permission", describeError(error));
    } finally {
      setBusy(false);
    }
  }

  async function flip(grantId: string, next: "read" | "write") {
    const current = project();
    if (!current) return;
    try {
      await api.setGrantAccess(current.id, grantId, next);
      await refreshProjectData(current.id);
      toast("info", next === "write" ? "Now read-write" : "Now read-only", "Restart the sandbox to apply.");
    } catch (error) {
      toast("error", "Could not change that permission", describeError(error));
    }
  }

  async function revoke(grantId: string, label: string) {
    const current = project();
    if (!current) return;
    try {
      await api.revokeGrant(current.id, grantId);
      await refreshProjectData(current.id);
      toast("ok", `Revoked ${label}`, "Restart the sandbox to detach it.");
    } catch (error) {
      toast("error", "Could not revoke that permission", describeError(error));
    }
  }

  return (
    <div class="panel">
      <Show when={project()} fallback={<div class="empty">Select a project first.</div>}>
        {(current) => (
          <>
            <div class="card">
              <h3>Network access</h3>
              <div class="row-inline" style={{ "flex-wrap": "wrap" }}>
                <For
                  each={
                    [
                      { mode: "none" },
                      { mode: "internet" },
                      { mode: "restricted", allow: [] },
                      { mode: "full" },
                    ] as NetworkPolicy[]
                  }
                >
                  {(candidate) => (
                    <button
                      class="btn btn-sm"
                      aria-pressed={current().network.mode === candidate.mode}
                      style={
                        current().network.mode === candidate.mode
                          ? { "border-color": "var(--accent)", background: "var(--accent-soft)" }
                          : undefined
                      }
                      disabled={modeBusy()}
                      onClick={() => void chooseMode(candidate.mode)}
                    >
                      {networkLabel(candidate)}
                    </button>
                  )}
                </For>
              </div>
              <span class="hint">{networkDescription(current().network)}</span>

              <Show when={allowlist()} fallback={<span class="hint">Loading…</span>}>
                {(view) => (
                  <>
                    <Show when={!view().restricted}>
                      <div class="callout callout-warn" style={{ "margin-top": "0.7rem" }}>
                        This project is in <span class="mono">{view().mode}</span> mode, so the
                        allowlist below is not consulted. Choose <strong>Allowlisted</strong> above for
                        these entries to take effect.
                      </div>
                    </Show>

                    <div class="field" style={{ "margin-top": "0.8rem" }}>
                      <label for="allowlist-draft">
                        Allowed destinations for this project
                      </label>
                      <textarea
                        id="allowlist-draft"
                        value={allowlistDraft()}
                        spellcheck={false}
                        rows={8}
                        placeholder={
                          "registry.npmjs.org\n*.githubusercontent.com\ngithub.com/org/repo\n!tracker.example.com"
                        }
                        onInput={(event) => setAllowlistDraft(event.currentTarget.value)}
                      />
                      <span class="hint">
                        One entry per line. <span class="mono">host</span> matches exactly,{" "}
                        <span class="mono">*.host</span> its subdomains,{" "}
                        <span class="mono">host/path</span> only paths under that prefix (HTTP only —
                        a CONNECT tunnel hides the path), <span class="mono">!host</span> denies and
                        always wins, <span class="mono">re:^…$</span> is an anchored regular
                        expression.
                      </span>

                      <div class="row-inline" style={{ "margin-top": "0.5rem", "flex-wrap": "wrap" }}>
                        <For each={presets()}>
                          {(preset) => (
                            <button
                              class="btn btn-sm"
                              title={preset.entries.join(", ")}
                              onClick={() => setAllowlistDraft(preset.entries.join("\n"))}
                            >
                              Use {preset.name} preset
                            </button>
                          )}
                        </For>
                        <button
                          class="btn btn-primary"
                          disabled={allowlistBusy() || !view().restricted}
                          onClick={() => void saveAllowlist()}
                        >
                          {allowlistBusy() ? "Saving…" : "Save allowlist"}
                        </button>
                      </div>

                      <Show when={view().problems.length > 0}>
                        <div class="callout callout-danger" style={{ "margin-top": "0.5rem" }}>
                          <strong>Not enforced — these entries would do nothing:</strong>
                          <ul style={{ margin: "0.3rem 0 0 1rem" }}>
                            <For each={view().problems}>
                              {(problem) => <li class="small">{problem}</li>}
                            </For>
                          </ul>
                        </div>
                      </Show>

                      <Show when={view().risky.length > 0}>
                        <div class="callout callout-warn" style={{ "margin-top": "0.5rem" }}>
                          <strong>In force, but very broad:</strong>{" "}
                          <span class="mono">{view().risky.join(", ")}</span>. These allow far more
                          than the hosts they name; consider narrowing them.
                        </div>
                      </Show>

                      <details style={{ "margin-top": "0.5rem" }}>
                        <summary class="small muted">
                          Show all {view().effective.length} entries in force (including{" "}
                          {view().global.length} inherited from global settings)
                        </summary>
                        <pre class="output" style={{ "margin-top": "0.4rem" }}>
                          {view().effective.join("\n")}
                        </pre>
                        <span class="hint">
                          The global list is edited in the app-wide Settings dialog. Deny entries from
                          either list beat allow entries from the other, so a global{" "}
                          <span class="mono">!host</span> cannot be undone here.
                        </span>
                      </details>
                    </div>
                  </>
                )}
              </Show>
            </div>

            <div class="card">
              <h3>Inside the sandbox right now</h3>
              <table>
                <thead>
                  <tr>
                    <th>Reachable at</th>
                    <th>Host path</th>
                    <th>Access</th>
                    <th>Origin</th>
                    <th />
                  </tr>
                </thead>
                <tbody>
                  <tr>
                    <td class="path">/workspace</td>
                    <td class="path">{current().rootDir}</td>
                    <td>
                      <span class="badge badge-accent">read-write</span>
                    </td>
                    <td class="muted small">the project itself</td>
                    <td class="muted small">always mounted</td>
                  </tr>
                  <For each={store.grants}>
                    {(grant) => (
                      <tr>
                        <td class="path">{grant.containerPath}</td>
                        <td class="path">{grant.hostPath}</td>
                        <td>
                          <span
                            class={
                              grant.access === "write" ? "badge badge-warn" : "badge badge-ok"
                            }
                          >
                            {accessLabel(grant.access)}
                          </span>
                        </td>
                        <td class="muted small">{grant.source}</td>
                        <td>
                          <div class="row-inline">
                            <Show
                              when={grant.access === "write"}
                              fallback={
                                <button
                                  class="btn btn-sm"
                                  title="Allow DeepCode to modify this directory"
                                  onClick={() => void flip(grant.id, "write")}
                                >
                                  Allow write
                                </button>
                              }
                            >
                              <button
                                class="btn btn-sm"
                                title="Downgrade to read-only"
                                onClick={() => void flip(grant.id, "read")}
                              >
                                Make read-only
                              </button>
                            </Show>
                            <button
                              class="btn btn-sm btn-danger"
                              onClick={() => void revoke(grant.id, grant.label)}
                            >
                              Revoke
                            </button>
                          </div>
                        </td>
                      </tr>
                    )}
                  </For>
                </tbody>
              </table>
              <Show when={store.grants.length === 0}>
                <p class="muted small" style={{ "margin-top": "0.6rem" }}>
                  No extra directories are shared. The sandbox can only see{" "}
                  <span class="mono">/workspace</span>.
                </p>
              </Show>
              <Show when={!current().running}>
                <p class="faint small" style={{ "margin-top": "0.6rem" }}>
                  Changes take effect when the sandbox next starts.
                </p>
              </Show>
            </div>

            <div class="card">
              <h3>Share another directory</h3>
              <p>
                Only the directories you list here become visible. Deepsand refuses system directories, your home
                folder, credential stores, anything overlapping its own state, and any path that would nest inside
                another share.
              </p>
              <div class="stack" style={{ "margin-top": "0.75rem" }}>
                <div class="field">
                  <label for="grant-path">Directory on this machine</label>
                  <div class="row-inline">
                    <input
                      id="grant-path"
                      class="grow"
                      type="text"
                      placeholder="D:\work\brand-assets"
                      value={draftPath()}
                      onInput={(event) => setDraftPath(event.currentTarget.value)}
                      onChange={(event) => void check(event.currentTarget.value)}
                    />
                    <button class="btn" onClick={() => void browse()}>
                      Browse…
                    </button>
                  </div>
                  <Show when={checkNote()}>
                    {(note) => (
                      <div class={note().ok ? "callout callout-info" : "callout callout-danger"}>
                        {note().text}
                      </div>
                    )}
                  </Show>
                </div>

                <div class="field">
                  <label>Access level</label>
                  <div class="access-choice">
                    <button
                      class="access-option"
                      aria-pressed={draftAccess() === "read"}
                      onClick={() => setDraftAccess("read")}
                    >
                      <strong>Read-only</strong>
                      <span>DeepCode can read files but cannot change or delete anything. Prefer this.</span>
                    </button>
                    <button
                      class="access-option"
                      aria-pressed={draftAccess() === "write"}
                      onClick={() => setDraftAccess("write")}
                    >
                      <strong>Read-write</strong>
                      <span>DeepCode can create, modify and delete files in this directory.</span>
                    </button>
                  </div>
                </div>

                <div class="field">
                  <label for="grant-purpose">Why (optional)</label>
                  <input
                    id="grant-purpose"
                    type="text"
                    placeholder="brand palette and logos"
                    value={draftPurpose()}
                    onInput={(event) => setDraftPurpose(event.currentTarget.value)}
                  />
                </div>

                <div class="row-inline">
                  <button
                    class="btn btn-primary"
                    disabled={busy() || !draftPath().trim() || checkNote()?.ok === false}
                    onClick={() => void add()}
                  >
                    Add permission
                  </button>
                </div>
              </div>
            </div>

            <div class="card">
              <h3>Decision log</h3>
              <p>Every grant, revoke and refusal for this project, newest last.</p>
              <Show
                when={store.audit.length > 0}
                fallback={<div class="empty">Nothing has been decided yet.</div>}
              >
                <pre class="output">{store.audit.join("\n")}</pre>
              </Show>
            </div>
          </>
        )}
      </Show>
    </div>
  );
}
