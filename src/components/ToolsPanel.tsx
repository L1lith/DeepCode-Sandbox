/**
 * The Tools tab and the thinking-intensity slider.
 *
 * Both save on change rather than behind a Save button: they are switches, and a
 * switch that needs confirming is not a switch. Each says what it will do before it
 * does it, because both change what the sandbox can do.
 */

import { createMemo, createSignal, For, onMount, Show } from "solid-js";
import * as api from "../lib/api";
import type { EffortView, ToolCatalogView, ToolView } from "../lib/types";
import { describeError, selectedProject, toast } from "../store";

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

  // Reload when the project changes, so one project's setting is never shown under
  // another project's name.
  createMemo(() => {
    const current = project();
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
