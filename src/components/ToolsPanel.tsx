/**
 * The Tools tab and the thinking-intensity slider.
 *
 * Both save on change rather than behind a Save button: they are switches, and a
 * switch that needs confirming is not a switch. Each says what it will do before it
 * does it, because both change what the sandbox can do.
 */

import { createMemo, createSignal, For, onMount, Show } from "solid-js";
import * as api from "../lib/api";
import type { EffortView, ModelChoice, ModelView, ToolCatalogView, ToolView } from "../lib/types";
import { describeError, selectedProject, store, toast } from "../store";
import { Modal } from "./Dialogs";

/* ------------------------------------------------------------------------- */
/* Model                                                                     */
/* ------------------------------------------------------------------------- */

/**
 * The model the sandbox runs, chosen from the ones the configured API offers.
 *
 * It sits beside Run because it decides what the agent *is*, not what it can reach: the list
 * comes from the project's own API, and the request for it is made by the app rather than from
 * here, because it is signed with a key that must not reach the window.
 *
 * "Defer to Config" is the default and means exactly that -- the project keeps no model of its
 * own, and whatever configuration resolves to is what runs, which is what the label names so it
 * can be read without opening anything. "Custom" is there because an API's list is never the
 * whole story: a private build, a proxy alias, or a name that has not been published yet can
 * still be typed in, and is used as it is.
 */
export function ModelSelect() {
  const [view, setView] = createSignal<ModelView | null>(null);
  const [busy, setBusy] = createSignal(false);
  /** The name being typed into the Custom dialog, or null when it is closed. */
  const [custom, setCustom] = createSignal<string | null>(null);

  const project = () => selectedProject();
  const CUSTOM = "__custom__";

  onMount(() => {
    const current = project();
    if (current) void load(current.id);
  });

  // Reload when the project changes, so one project's model is never shown under another
  // project's name, and when the host's settings file changes, because what "Defer to Config"
  // resolves to is read from it.
  createMemo(() => {
    const current = project();
    const revision = store.configRevision;
    void revision;
    if (current) void load(current.id);
  });

  async function load(projectId: string) {
    try {
      // What the project is set to first: that answer is local, so the control works at once.
      setView(await api.getModel(projectId));
    } catch {
      // A project whose setting cannot be read shows no dropdown rather than a wrong one.
      setView(null);
      return;
    }
    try {
      // Then the list, which is a request to the project's API and may be slow or refused.
      const listed = await api.listModels(projectId);
      if (project()?.id === projectId) setView(listed);
    } catch {
      /* The saved value is already on screen; the list is a convenience, not the setting. */
    }
  }

  /** The listed models, plus whatever this project runs if the list does not mention it. */
  function options(): ModelChoice[] {
    const current = view();
    if (!current) return [];
    const chosen = current.value;
    if (chosen && !current.options.some((model) => model.id === chosen)) {
      return [{ id: chosen, name: chosen }, ...current.options];
    }
    return current.options;
  }

  function labelFor(id: string): string {
    return options().find((model) => model.id === id)?.name ?? id;
  }

  function sayWhatHappened(saved: ModelView, what: string) {
    toast(
      "ok",
      saved.deferring ? "Model: following configuration" : `Model: ${what}`,
      saved.deferring
        ? `Using ${saved.configured} from your configuration.`
        : saved.appliedLive
          ? "Written into the running sandbox's settings."
          : "Saved. It applies when this project next runs.",
    );
  }

  async function choose(value: string) {
    const current = project();
    if (!current || busy()) return;

    if (value === CUSTOM) {
      setCustom(view()?.value ?? view()?.configured ?? "");
      return;
    }

    setBusy(true);
    try {
      const saved = await api.setModel(current.id, value === "" ? null : value);
      setView(saved);
      // The name if the list has one, so the toast reads like the dropdown.
      sayWhatHappened(saved, labelFor(value));
    } catch (error) {
      toast("error", "Could not change the model", describeError(error));
      // Put the control back to what is saved, rather than leaving it showing a choice that
      // was refused.
      setView(await api.getModel(current.id).catch(() => view()));
    } finally {
      setBusy(false);
    }
  }

  async function saveCustom(name: string) {
    const current = project();
    if (!current || busy()) return;
    setBusy(true);
    try {
      const saved = await api.setModel(current.id, name);
      setView(saved);
      setCustom(null);
      sayWhatHappened(saved, name);
    } catch (error) {
      toast("error", "Could not set that model", describeError(error));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Show when={view()}>
      {(current) => (
        <>
          <select
            class="model-select"
            disabled={busy()}
            title={
              current().problem ??
              `The model this project runs. Defer to Config follows the configured model${
                current().configured ? ` (${current().configured})` : ""
              }.`
            }
            value={current().value ?? ""}
            onChange={(event) => void choose(event.currentTarget.value)}
          >
            <option value="">
              Defer to Config{current().configured ? ` (${current().configured})` : ""}
            </option>
            <For each={options()}>
              {(model) => (
                <option value={model.id} title={model.id}>
                  {model.name}
                </option>
              )}
            </For>
            <option value={CUSTOM}>Custom…</option>
          </select>
          {/* The list is a network call; when it fails the dropdown is still usable, and this
              is what says why it is short. */}
          <Show when={current().problem}>
            <span class="model-warning" title={current().problem ?? ""}>
              !
            </span>
          </Show>
          <Show when={custom() !== null}>
            <CustomModelDialog
              initial={custom() ?? ""}
              busy={busy()}
              onClose={() => setCustom(null)}
              onSave={(name) => void saveCustom(name)}
            />
          </Show>
        </>
      )}
    </Show>
  );
}

/** Type a model name that the API's list does not have. */
function CustomModelDialog(props: {
  initial: string;
  busy: boolean;
  onClose: () => void;
  onSave: (name: string) => void;
}) {
  const [name, setName] = createSignal(props.initial);
  const ready = () => name().trim().length > 0 && !props.busy;

  function save() {
    if (ready()) props.onSave(name().trim());
  }

  return (
    <Modal
      title="Custom model"
      subtitle="Used exactly as written: nothing checks it against the API's list."
      onClose={props.onClose}
      footer={
        <>
          <button class="btn btn-danger left" disabled={props.busy} onClick={props.onClose}>
            Cancel
          </button>
          <button class="btn btn-primary" disabled={!ready()} onClick={save}>
            Use this model
          </button>
        </>
      }
    >
      <label class="field">
        <span>Model name</span>
        <input
          autofocus
          value={name()}
          placeholder="e.g. deepseek-v4-pro"
          onInput={(event) => setName(event.currentTarget.value)}
          onKeyDown={(event) => {
            if (event.key === "Enter") save();
          }}
        />
      </label>
      <p class="small">
        Goes into the sandbox's <span class="mono">MODEL</span> setting as typed. Leave the
        dropdown on Defer to Config to go back to the configured model.
      </p>
    </Modal>
  );
}

/* ------------------------------------------------------------------------- */
/* Thinking intensity                                                        */
/* ------------------------------------------------------------------------- */

/**
 * A five-stop slider beside Run.
 *
 * A real `input[type=range]` rather than a row of buttons, so it drags, responds to
 * arrow keys, and announces itself correctly. The filled part of the track is painted
 * with a gradient driven by `--fill`, which is the one thing a native range cannot be
 * told to do by itself.
 *
 * Committing happens on `change` (pointer release, or a key press) rather than on
 * `input`, so dragging across five stops sends one request instead of five. The thumb
 * still tracks the pointer, because `input` moves the local value.
 */
export function EffortSwitch() {
  const [view, setView] = createSignal<EffortView | null>(null);
  const [dragged, setDragged] = createSignal<number | null>(null);
  const [busy, setBusy] = createSignal(false);

  const project = () => selectedProject();

  onMount(() => {
    const current = project();
    if (current) void load(current.id);
  });

  // Reload when the project changes, so one project's setting is never shown under another
  // project's name, and when the host's settings file changes: whether this switch is deferring
  // to it is exactly what that file decides.
  createMemo(() => {
    const current = project();
    const revision = store.configRevision;
    void revision;
    if (current) void load(current.id);
  });

  async function load(projectId: string) {
    try {
      setView(await api.getEffort(projectId));
      setDragged(null);
    } catch {
      // A project whose setting cannot be read simply shows no slider.
      setView(null);
    }
  }

  const options = () => view()?.options ?? [];

  /** The stop on show: the dragged one if there is one, otherwise the saved one. */
  const index = createMemo(() => {
    const current = view();
    if (!current) return 0;
    const held = dragged();
    if (held !== null) return held;
    return Math.max(
      0,
      current.options.findIndex((option) => option.value === current.value),
    );
  });

  const active = () => options()[index()];
  const lastIndex = () => Math.max(1, options().length - 1);

  async function commit(at: number) {
    const current = project();
    const option = options()[at];
    if (!current || !option || busy()) {
      setDragged(null);
      return;
    }
    // Already there: nothing to send.
    if (option.value === view()?.value) {
      setDragged(null);
      return;
    }

    const previous = view();
    setBusy(true);
    try {
      const saved = await api.setEffort(current.id, option.value);
      setView(saved);
      setDragged(null);
      toast(
        "ok",
        `Thinking: ${option.label}`,
        saved.deferring
          ? "Following your own DeepCode settings.json."
          : saved.appliedLive
            ? "Applied to the running sandbox."
            : "Saved. It applies when this project next runs.",
      );
    } catch (error) {
      setView(previous);
      setDragged(null);
      toast("error", "Could not change the thinking intensity", describeError(error));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Show when={view() && options().length > 0}>
      <div class="effort" classList={{ "effort-busy": busy() }}>
        <span class="effort-value" title={active()?.description}>
          {active()?.label ?? "…"}
        </span>
        <div class="effort-track">
          <input
            class="effort-slider"
            type="range"
            min={0}
            max={lastIndex()}
            step={1}
            value={index()}
            disabled={busy()}
            aria-label="Thinking intensity"
            aria-valuetext={active()?.label}
            title={active()?.description}
            style={{ "--fill": `${(index() / lastIndex()) * 100}%` }}
            onInput={(event) => setDragged(Number(event.currentTarget.value))}
            onChange={(event) => void commit(Number(event.currentTarget.value))}
          />
          {/* Tick marks, so the stops are visible without labels competing for room. */}
          <div class="effort-ticks" aria-hidden="true">
            <For each={options()}>
              {(_, at) => <span class="effort-tick" classList={{ on: at() <= index() }} />}
            </For>
          </div>
        </div>
      </div>
    </Show>
  );
}

/* ------------------------------------------------------------------------- */
/* Tools                                                                     */
/* ------------------------------------------------------------------------- */

/** One row: the description on the left, a switch on the right. */
function ToolRow(props: {
  tool: ToolView;
  busy: boolean;
  onToggle: (id: string, enabled: boolean) => void;
}) {
  const locked = () => !props.tool.available;
  const opensNetwork = () => !locked() && props.tool.enabled && props.tool.hosts.length > 0;

  return (
    <div class="tool-row" classList={{ "tool-off": locked() }}>
      <div class="tool-body">
        <div class="tool-head">
          <span class="tool-name">{props.tool.label}</span>
          <Show when={props.tool.defaultOn && !locked()}>
            <span class="chip chip-quiet" title="On for a new project unless switched off">
              default
            </span>
          </Show>
          <Show when={locked()}>
            <span class="chip chip-warn" title={props.tool.unavailableReason ?? ""}>
              needs {props.tool.requires}
            </span>
          </Show>
          <Show when={opensNetwork()}>
            <span class="chip chip-accent">opens the network</span>
          </Show>
        </div>

        <p class="tool-desc">{props.tool.description}</p>

        {/* Before the switch, not after it: this is the only warning about a cost the operator
            would otherwise discover on the next build. */}
        <Show when={props.tool.costNote}>
          {(note) => <p class="tool-note tool-note-warn">{note()}</p>}
        </Show>

        <Show when={locked()}>
          <p class="tool-note tool-note-warn">{props.tool.unavailableReason}</p>
        </Show>

        <Show when={opensNetwork()}>
          <p class="tool-note">
            Reaches <span class="mono">{props.tool.hosts.join(", ")}</span> while switched on, and
            stops the moment it is switched off.
          </p>
        </Show>

        <Show when={!locked()}>
          <p class="tool-meta">Installed with {props.tool.provider}</p>
        </Show>
      </div>

      <button
        class="switch"
        role="switch"
        aria-checked={props.tool.enabled}
        aria-label={`${props.tool.label}${locked() ? " (not available here)" : ""}`}
        title={
          locked()
            ? (props.tool.unavailableReason ?? `Needs a ${props.tool.requires} image`)
            : props.tool.enabled
              ? "Switch off"
              : "Switch on"
        }
        disabled={locked() || props.busy}
        onClick={() => props.onToggle(props.tool.id, !props.tool.enabled)}
      >
        <span class="switch-knob" />
      </button>
    </div>
  );
}

/** The distinct hosts a set of tools would open, sorted. */
function hostsOf(tools: ToolView[]): string[] {
  return [...new Set(tools.flatMap((tool) => tool.hosts))].sort();
}

export function ToolsPanel() {
  const [catalog, setCatalog] = createSignal<ToolCatalogView | null>(null);
  const [busy, setBusy] = createSignal(false);

  const project = () => selectedProject();

  onMount(() => {
    const current = project();
    if (current) void load(current.id);
  });

  // Reload when the selection changes, so switching projects never shows the last
  // project's tools.
  createMemo(() => {
    const current = project();
    if (current) void load(current.id);
  });

  async function load(projectId: string) {
    try {
      setCatalog(await api.listTools(projectId));
    } catch (error) {
      toast("error", "Could not read this project's tools", describeError(error));
    }
  }

  const tools = () => catalog()?.tools ?? [];

  /**
   * Replace the whole selection in one request.
   *
   * The bulk buttons use this rather than looping over `toggle`: one round trip instead
   * of one per tool, and no moment where the selection is half-applied and the image
   * tag is wrong for neither state.
   */
  async function applySelection(
    ids: string[],
    message: { title: string; detail: string },
  ): Promise<void> {
    const current = project();
    if (!current || !catalog() || busy()) return;
    setBusy(true);
    try {
      const saved = await api.setProjectTools(current.id, ids);
      setCatalog(saved);
      toast("ok", message.title, message.detail);
    } catch (error) {
      toast("error", "Could not change the tools", describeError(error));
    } finally {
      setBusy(false);
    }
  }

  /** Enable every tool a category can hold, leaving the rest of the selection alone. */
  function enableCategory(group: { tools: ToolView[]; category: string }) {
    const actionable = group.tools.filter((tool) => tool.available && !tool.enabled);
    if (actionable.length === 0) return;
    const ids = [
      ...tools().filter((tool) => tool.enabled).map((tool) => tool.id),
      ...actionable.map((tool) => tool.id),
    ];
    const hosts = hostsOf(actionable);
    void applySelection(ids, {
      title: `All ${group.category.toLowerCase()} on (${actionable.length})`,
      detail:
        (hosts.length > 0 ? `Network opened: ${hosts.join(", ")}. ` : "") +
        "Rebuild the image to install them.",
    });
  }

  function disableCategory(group: { tools: ToolView[]; category: string }) {
    const actionable = group.tools.filter((tool) => tool.enabled);
    if (actionable.length === 0) return;
    const off = new Set(actionable.map((tool) => tool.id));
    void applySelection(
      tools()
        .filter((tool) => tool.enabled && !off.has(tool.id))
        .map((tool) => tool.id),
      {
        title: `All ${group.category.toLowerCase()} off (${actionable.length})`,
        detail:
          (hostsOf(actionable).length > 0
            ? `Network closed again: ${hostsOf(actionable).join(", ")}. `
            : "") + "Rebuild the image to remove them.",
      },
    );
  }

  function enableEverything() {
    const actionable = tools().filter((tool) => tool.available && !tool.enabled);
    if (actionable.length === 0) return;
    const hosts = hostsOf(actionable);
    void applySelection(
      tools()
        .filter((tool) => tool.available)
        .map((tool) => tool.id),
      {
        title: `Every tool on (${tools().filter((t) => t.available).length})`,
        // The widest change this panel can make, so it says what it opened rather than
        // just reporting a count.
        detail:
          (hosts.length > 0 ? `Network opened: ${hosts.join(", ")}. ` : "") +
          "This is the largest image Deepsand can build. Rebuild to install everything.",
      },
    );
  }

  function disableEverything() {
    const on = tools().filter((tool) => tool.enabled);
    if (on.length === 0) return;
    const hosts = hostsOf(on);
    void applySelection([], {
      title: "Every tool off",
      detail:
        (hosts.length > 0 ? `Network closed again: ${hosts.join(", ")}. ` : "") +
        "The next build produces a bare image, with no git, jq or ripgrep.",
    });
  }

  async function toggle(id: string, enabled: boolean) {
    const current = project();
    const view = catalog();
    if (!current || !view || busy()) return;
    const ids = view.tools
      .filter((tool) => (tool.id === id ? enabled : tool.enabled))
      .map((tool) => tool.id);
    setBusy(true);
    try {
      const saved = await api.setProjectTools(current.id, ids);
      setCatalog(saved);
      const tool = saved.tools.find((candidate) => candidate.id === id);
      const hosts = tool?.hosts ?? [];
      toast(
        "ok",
        `${tool?.label ?? id} ${enabled ? "enabled" : "disabled"}`,
        enabled && hosts.length > 0
          ? `Also allowed: ${hosts.join(", ")}. Rebuild the image to install it.`
          : enabled
            ? "Rebuild the image to install it."
            : hosts.length > 0
              ? `Closed again: ${hosts.join(", ")}.`
              : "Rebuild the image so it takes effect.",
      );
    } catch (error) {
      toast("error", "Could not change the tools", describeError(error));
    } finally {
      setBusy(false);
    }
  }

  /**
   * The catalogue grouped by category, preserving the catalogue's own order.
   *
   * `enabled` and `available` are counted here rather than in the markup so the bulk
   * buttons can be disabled when they would do nothing -- an "Enable all" that is
   * already true is a button that only produces a confusing toast.
   */
  const groups = createMemo(() => {
    const view = catalog();
    if (!view) return [];
    const order: string[] = [];
    const byCategory = new Map<string, ToolView[]>();
    for (const tool of view.tools) {
      if (!byCategory.has(tool.category)) {
        byCategory.set(tool.category, []);
        order.push(tool.category);
      }
      byCategory.get(tool.category)!.push(tool);
    }
    return order.map((category) => {
      const list = byCategory.get(category)!;
      return {
        category,
        tools: list,
        enabled: list.filter((tool) => tool.enabled).length,
        // Only these can be switched on, so they are what "all" means for a category.
        available: list.filter((tool) => tool.available).length,
        canEnable: list.some((tool) => tool.available && !tool.enabled),
        canDisable: list.some((tool) => tool.enabled),
      };
    });
  });

  const unavailable = createMemo(() => tools().filter((tool) => !tool.available).length);
  const enableableTools = createMemo(() => tools().filter((tool) => tool.available).length);
  const canEnableAnything = createMemo(() => tools().some((tool) => tool.available && !tool.enabled));
  const canDisableAnything = createMemo(() => tools().some((tool) => tool.enabled));

  return (
    <div class="panel">
      <Show when={catalog()} fallback={<div class="empty">Loading tools…</div>}>
        {(view) => (
          <>
            <div class="card">
              <div class="card-head">
                <h3>Tools</h3>
                <span class="chip chip-quiet mono" title="The image tag this selection builds to">
                  {view().image}
                </span>
              </div>
              <p class="muted small">
                Tools are built into this project's container image, so a change here needs the image
                rebuilt before it takes effect. A tool that needs the network also opens the hosts it
                uses while it is switched on, and closes them again when switched off.
              </p>
              <Show when={view().effectiveHosts.length > 0}>
                <p class="muted small">
                  Open for this project right now:{" "}
                  <span class="mono">{view().effectiveHosts.join(", ")}</span>
                </p>
              </Show>
              <Show when={unavailable() > 0}>
                <p class="muted small">
                  {unavailable()} tool{unavailable() === 1 ? " is" : "s are"} greyed out and cannot be
                  switched on, because the sandbox image is not the one they need.
                </p>
              </Show>

              <div class="bulk-row">
                <span class="bulk-label">Whole catalogue</span>
                <button
                  class="btn btn-ghost btn-sm"
                  disabled={busy() || !canEnableAnything()}
                  title="Switch on every tool this image can hold, including package managers"
                  onClick={enableEverything}
                >
                  Enable all tools
                </button>
                <button
                  class="btn btn-ghost btn-sm"
                  disabled={busy() || !canDisableAnything()}
                  title="Switch everything off, including git, jq and ripgrep"
                  onClick={disableEverything}
                >
                  Disable all tools
                </button>
                <span class="bulk-count">
                  {enableableTools()} available
                  <Show when={unavailable() > 0}> · {unavailable()} not for this image</Show>
                </span>
              </div>
            </div>

            <For each={groups()}>
              {(group) => (
                <div class="card">
                  <div class="card-head">
                    <h3>{group.category}</h3>
                    <span class="chip chip-quiet">
                      {group.enabled} of {group.tools.length} on
                    </span>
                  </div>

                  <div class="bulk-row">
                    <button
                      class="btn btn-ghost btn-sm"
                      disabled={busy() || !group.canEnable}
                      title={`Switch on every available tool in ${group.category}`}
                      onClick={() => enableCategory(group)}
                    >
                      Enable all
                    </button>
                    <button
                      class="btn btn-ghost btn-sm"
                      disabled={busy() || !group.canDisable}
                      title={`Switch off every tool in ${group.category}`}
                      onClick={() => disableCategory(group)}
                    >
                      Disable all
                    </button>
                    <Show when={group.available < group.tools.length}>
                      <span class="bulk-count">
                        {group.tools.length - group.available} not for this image
                      </span>
                    </Show>
                  </div>

                  <div class="tool-list">
                    <For each={group.tools}>
                      {(tool) => <ToolRow tool={tool} busy={busy()} onToggle={toggle} />}
                    </For>
                  </div>
                </div>
              )}
            </For>
          </>
        )}
      </Show>
    </div>
  );
}
