/**
 * The Secrets tab.
 *
 * Values go one way only. Nothing the backend returns contains a secret, so the table
 * can only ever show that one exists -- which is also why there is no reveal toggle:
 * there would be nothing for it to reveal.
 *
 * The reason to have this at all is that a secret in the sandbox's environment is
 * visible to everything running in the sandbox. That is the point -- the agent needs
 * it to build -- but it means a broad network allowlist is a way for a secret to
 * leave. The panel says so where the operator can see it while deciding.
 */

import { createMemo, createSignal, For, onMount, Show } from "solid-js";
import * as api from "../lib/api";
import type { SecretListView } from "../lib/types";
import { describeError, selectedProject, toast } from "../store";

export function SecretsPanel() {
  const [view, setView] = createSignal<SecretListView | null>(null);
  const [busy, setBusy] = createSignal(false);
  const [name, setName] = createSignal("");
  const [value, setValue] = createSignal("");
  const [editing, setEditing] = createSignal<string | null>(null);
  const [editValue, setEditValue] = createSignal("");

  const project = () => selectedProject();

  onMount(() => {
    const current = project();
    if (current) void load(current.id);
  });

  // Reload when the selection changes, so one project's secrets are never shown
  // under another project's name.
  createMemo(() => {
    const current = project();
    if (current) void load(current.id);
  });

  async function load(projectId: string) {
    try {
      setView(await api.listSecrets(projectId));
    } catch (error) {
      toast("error", "Could not read this project's secrets", describeError(error));
    }
  }

  const nameProblem = createMemo(() => {
    const candidate = name().trim();
    if (!candidate) return null;
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(candidate)) {
      return "Use letters, digits and underscores, starting with a letter or underscore.";
    }
    const upper = candidate.toUpperCase();
    if (upper.startsWith("DEEPSAND_")) {
      return "Names starting with DEEPSAND_ are reserved.";
    }
    if ((view()?.reserved ?? []).includes(upper)) {
      return `${upper} is reserved, because the sandbox itself uses it.`;
    }
    return null;
  });

  async function add() {
    const current = project();
    if (!current || busy() || nameProblem()) return;
    setBusy(true);
    try {
      const saved = await api.setSecret(current.id, name().trim(), value());
      setView(saved);
      toast(
        "ok",
        `${name().trim()} saved`,
        saved.restartNeeded
          ? "Encrypted and stored. Restart the sandbox so it reaches the container."
          : "Encrypted and stored. It will be in the environment next time this project runs.",
      );
      setName("");
      setValue("");
    } catch (error) {
      toast("error", "Could not save the secret", describeError(error));
    } finally {
      setBusy(false);
    }
  }

  async function replace(target: string) {
    const current = project();
    if (!current || busy() || !editValue()) return;
    setBusy(true);
    try {
      const saved = await api.setSecret(current.id, target, editValue());
      setView(saved);
      setEditing(null);
      setEditValue("");
      toast("ok", `${target} replaced`, "The old value is gone; it was overwritten, not kept.");
    } catch (error) {
      toast("error", "Could not replace the secret", describeError(error));
    } finally {
      setBusy(false);
    }
  }

  async function remove(target: string) {
    const current = project();
    if (!current || busy()) return;
    setBusy(true);
    try {
      const saved = await api.deleteSecret(current.id, target);
      setView(saved);
      toast("ok", `${target} removed`, "Removed from the store and from the sandbox environment.");
    } catch (error) {
      toast("error", "Could not remove the secret", describeError(error));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div class="panel">
      <Show when={view()} fallback={<div class="empty">Loading secrets…</div>}>
        {(current) => (
          <>
            <div class="card">
              <h3>Secrets for this project</h3>
              <p class="muted small">
                Stored encrypted, keyed from your operating system's keystore — not in the project
                directory, not in the repository, and never in the audit log. They are handed to the
                container as environment variables, so anything running inside the sandbox can read
                them, which is what makes them useful and also what makes a broad network allowlist
                a way for one to leave.
              </p>
              <Show when={current().restartNeeded}>
                <div class="callout callout-warn">
                  A sandbox is running. Changes here are stored straight away but reach the container
                  on its next start, so restart the sandbox after editing.
                </div>
              </Show>
              <Show when={!current().available}>
                <div class="callout callout-danger">{current().unavailableReason}</div>
              </Show>
            </div>

            <Show when={current().available}>
              <div class="card">
                <h3>Stored</h3>
                <Show
                  when={current().secrets.length > 0}
                  fallback={
                    <div class="empty">
                      No secrets yet. Anything this project needs — an API key, a database URL — can go
                      here rather than in a file in the repository.
                    </div>
                  }
                >
                  <table class="secret-table">
                    <thead>
                      <tr>
                        <th>Name</th>
                        <th>Value</th>
                        <th class="num">Length</th>
                        <th class="actions" />
                      </tr>
                    </thead>
                    <tbody>
                      <For each={current().secrets}>
                        {(secret) => (
                          <tr>
                            <td class="mono">{secret.name}</td>
                            <td class="mono faint">{secret.masked}</td>
                            <td class="num faint">{secret.length}</td>
                            <td class="actions">
                              <Show
                                when={editing() === secret.name}
                                fallback={
                                  <>
                                    <button
                                      class="btn btn-ghost small"
                                      disabled={busy()}
                                      onClick={() => {
                                        setEditing(secret.name);
                                        setEditValue("");
                                      }}
                                    >
                                      Replace
                                    </button>
                                    <button
                                      class="btn btn-ghost small"
                                      disabled={busy()}
                                      onClick={() => void remove(secret.name)}
                                    >
                                      Remove
                                    </button>
                                  </>
                                }
                              >
                                <input
                                  type="password"
                                  class="grow"
                                  autocomplete="off"
                                  placeholder="new value"
                                  aria-label={`New value for ${secret.name}`}
                                  value={editValue()}
                                  onInput={(event) => setEditValue(event.currentTarget.value)}
                                  onKeyDown={(event) => {
                                    if (event.key === "Enter") void replace(secret.name);
                                    if (event.key === "Escape") setEditing(null);
                                  }}
                                />
                                <button
                                  class="btn btn-primary small"
                                  disabled={busy() || !editValue()}
                                  onClick={() => void replace(secret.name)}
                                >
                                  Save
                                </button>
                                <button
                                  class="btn btn-ghost small"
                                  onClick={() => {
                                    setEditing(null);
                                    setEditValue("");
                                  }}
                                >
                                  Cancel
                                </button>
                              </Show>
                            </td>
                          </tr>
                        )}
                      </For>
                    </tbody>
                  </table>
                </Show>
              </div>

              <div class="card">
                <h3>Add a secret</h3>
                <div class="row-inline">
                  <input
                    class="grow"
                    type="text"
                    placeholder="MY_API_KEY"
                    aria-label="Secret name"
                    autocomplete="off"
                    value={name()}
                    onInput={(event) => setName(event.currentTarget.value)}
                  />
                  <input
                    class="grow"
                    type="password"
                    placeholder="value"
                    aria-label="Secret value"
                    autocomplete="off"
                    value={value()}
                    onInput={(event) => setValue(event.currentTarget.value)}
                    onKeyDown={(event) => {
                      if (event.key === "Enter") void add();
                    }}
                  />
                  <button
                    class="btn btn-primary"
                    disabled={busy() || !name().trim() || !value() || nameProblem() !== null}
                    onClick={() => void add()}
                  >
                    Add
                  </button>
                </div>
                <Show when={nameProblem()}>
                  {(problem) => <div class="hint tool-unavailable">{problem()}</div>}
                </Show>
                <span class="hint">
                  The name becomes an environment variable name, so it has to be one. Values are typed
                  one way: once saved they are never shown again, only replaced.
                </span>
              </div>
            </Show>
          </>
        )}
      </Show>
    </div>
  );
}
