/**
 * Modal dialogs.
 *
 * The most important one is `PermissionDialog`, which is the two prompts the
 * product is built around:
 *
 *  * "DeepCode is trying to access <path>" — the sandbox named a path, so the
 *    dialog shows exactly that path and the operator confirms.
 *  * "DeepCode is requesting access to <thing>" — the sandbox knows *what* it
 *    needs but not *where* it lives, so the operator is given a folder picker to
 *    locate it. The sandbox never learns the host path, only where the result
 *    appears inside itself.
 */

import { createEffect, createMemo, createSignal, For, onCleanup, onMount, Show, type JSX } from "solid-js";
import { open } from "@tauri-apps/plugin-dialog";
import * as api from "../lib/api";
import { baseName, shortPath } from "../lib/format";
import {
  DEFAULT_LIMITS,
  type AppSettings,
  type StartupMode,
  type PermissionRequestView,
  type ProjectView,
  type ResourceLimits,
  type RemoteAccessSettings,
  type RemoteAccessView,
  type RemoteServerConfig,
  type UpdateCheck,
  type UpdateProgress,
} from "../lib/types";
import {
  describeError,
  dismissToast,
  refreshProjects,
  refreshSettings,
  selectedProject,
  store,
  toast,
} from "../store";

/* ------------------------------------------------------------------------- */
/* Shared chrome                                                              */
/* ------------------------------------------------------------------------- */

export function Modal(props: {
  title: string;
  subtitle?: string;
  wide?: boolean;
  onClose: () => void;
  children: JSX.Element;
  footer: JSX.Element;
}) {
  return (
    <div
      class="scrim"
      onClick={(event) => {
        if (event.target === event.currentTarget) props.onClose();
      }}
    >
      <div class={props.wide ? "modal modal-wide" : "modal"} role="dialog" aria-modal="true">
        <div class="modal-head">
          <h2>{props.title}</h2>
          <Show when={props.subtitle}>
            <p>{props.subtitle}</p>
          </Show>
        </div>
        <div class="modal-body">{props.children}</div>
        <div class="modal-foot">{props.footer}</div>
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------------- */
/* Permission request dialog                                                  */
/* ------------------------------------------------------------------------- */

export function PermissionDialog(props: { request: PermissionRequestView; queued: number }) {
  const request = () => props.request;

  const [path, setPath] = createSignal(request().claimedPath ?? "");
  // A write request is a bigger ask, so it never arrives pre-selected.
  // Read-only is the default even when the sandbox asked for write: an approval
  // should be a deliberate act, not a keystroke that inherits the larger ask.
  const [access, setAccess] = createSignal<"read" | "write">("read");
  const [note, setNote] = createSignal("");
    const [busy, setBusy] = createSignal(false);
  const [check, setCheck] = createSignal<{ ok: boolean; text: string } | null>(null);

  // A new request may arrive while this one is open; re-seed the form.
  createEffect(() => {
    const current = request();
    setPath(current.claimedPath ?? "");
    setAccess("read");
    setNote("");
    setBusy(false);
    if (current.claimedPath) void verify(current.claimedPath);
    else setCheck(null);
  });

  async function verify(candidate: string) {
    if (!candidate.trim()) {
      setCheck(null);
      return;
    }
    try {
      const result = await api.pathCheck(candidate);
      setCheck(
        result.allowed
          ? { ok: true, text: `Allowed. It will appear inside the sandbox as ${"/grants/<name>"}.` }
          : { ok: false, text: result.reason ?? "This path cannot be shared." },
      );
    } catch (error) {
      setCheck({ ok: false, text: describeError(error) });
    }
  }

  async function locate() {
    const chosen = await open({
      directory: request().requestedKind !== "file",
      multiple: false,
      title: `Find ${request().description}`,
    });
    if (typeof chosen === "string") {
      setPath(chosen);
      await verify(chosen);
    }
  }

  const blocked = createMemo(() => check()?.ok === false);

  async function decide(decision: "allow" | "deny") {
    setBusy(true);
    try {
      const allowed = await api.answerRequest({
        requestId: request().id,
        decision,
        message: note(),
        hostPath: decision === "allow" ? path() : null,
        access: decision === "allow" ? access() : null,
        secretName: request().secretName ?? null,
        secretValue: request().secretValue ?? null,
        restart: true,
      });
      if (decision === "allow" && allowed) {
        toast(
          "ok",
          "Shared, and the sandbox is restarting",
          `${baseName(path())} is now visible to DeepCode.`,
        );
      } else if (decision === "deny") {
        toast("info", "Denied", "DeepCode was told the decision is final.");
      }
    } catch (error) {
      toast("error", "Could not deliver the decision", describeError(error));
    } finally {
      setBusy(false);
    }
  }

  /**
   * Turn permission requests off for this project, from the dialog itself.
   *
   * The host answers this request and every other one already waiting, so the dialog
   * closes because the request was *answered* rather than because the UI hid it — and the
   * sandbox is told why instead of being left waiting for a decision that is not coming.
   */
  async function stopAsking() {
    setBusy(true);
    try {
      await api.setRequestsEnabled(request().projectId, false);
      toast(
        "info",
        "DeepCode will not ask again",
        `${request().projectName} cannot request permissions until you turn it back on, in Permissions.`,
      );
    } catch (error) {
      toast("error", "Could not turn requests off", describeError(error));
    } finally {
      setBusy(false);
    }
  }

  /**
   * The two request kinds that are about a path on the operator's machine.
   *
   * Network and tool requests reuse the same dialog but have no path to choose, so
   * everything path-shaped is hidden for them rather than offering a folder picker
   * for a question that is not about folders.
   */
  const isDirectoryKind = () =>
    request().kind === "directory_access" || request().kind === "locate_resource";

  return (
    <Modal
      title={request().title}
      subtitle={`Project: ${request().projectName}`}
      onClose={() => void decide("deny")}
      footer={
        <>
          <span class="left">
            <Show when={props.queued > 1}>
              {props.queued - 1} more request{props.queued - 1 === 1 ? "" : "s"} waiting.
            </Show>
            {/* Deliberately quiet, and in the footer's spare space: it is the right answer
                to a flood and the wrong answer to the one request you are about to grant. */}
            <button
              class="btn btn-ghost btn-sm"
              style={{ "margin-left": props.queued > 1 ? "0.6rem" : "0" }}
              disabled={busy()}
              title={
                `Stop ${request().projectName} from asking for permissions at all. ` +
                "Anything already waiting is refused, and this request is refused too."
              }
              onClick={() => void stopAsking()}
            >
              Stop asking
            </button>
          </span>
          <button class="btn btn-danger" disabled={busy()} onClick={() => void decide("deny")}>
            Deny
          </button>
          <button
            class="btn btn-primary"
            // Only a directory request needs a path. Requiring one for every kind left the
            // button dead for the kinds that have no path at all: a network request could
            // not be approved, because the field it was waiting for is never shown.
            disabled={busy() || blocked() || (isDirectoryKind() && !path().trim())}
            onClick={() => void decide("allow")}
          >
            Grant access
          </button>
        </>
      }
    >
      <div class="stack">
        <div class="request-title">{request().title}</div>

        <Show when={request().purpose}>
          {(purpose) => (
            <div class="callout callout-info">
              <strong>What it says it needs it for:</strong> {purpose()}
            </div>
          )}
        </Show>

        <Show when={isDirectoryKind() && request().kind === "directory_access" && request().claimedPath}>
          <div class="field">
            <label>Path DeepCode named</label>
            <div class="request-path">{request().claimedPath}</div>
            <span class="hint">
              Deepsand re-checks this path itself. A path it refuses cannot be granted even if you allow it.
            </span>
          </div>
        </Show>

        {/* Not a control, a caveat. The spool this came from is writable by the
            sandbox, so the request is something the contained process wrote -- and a
            dialog that does not say so invites reading it as a finding. */}
        <p class="muted small request-provenance">{request().provenance}</p>

        <Show when={isDirectoryKind() && (request().kind === "locate_resource" || !request().claimedPath)}>
          <div class="callout callout-warn">
            DeepCode cannot see where this lives on your machine, so pick the folder yourself. It will be told only
            where the folder appears inside the sandbox — never the host path.
          </div>
        </Show>

        <Show when={isDirectoryKind()}>
        <div class="field">
          <label for="perm-path">
            {request().kind === "locate_resource" ? "The directory on this machine" : "Directory to share"}
          </label>
          <div class="row-inline">
            <input
              id="perm-path"
              class="grow"
              type="text"
              placeholder="D:\work\brand-assets"
              value={path()}
              onInput={(event) => setPath(event.currentTarget.value)}
              onChange={(event) => void verify(event.currentTarget.value)}
            />
            <button class="btn" onClick={() => void locate()}>
              Locate…
            </button>
          </div>
          <Show when={check()}>
            {(result) => (
              <div class={result().ok ? "callout callout-info" : "callout callout-danger"}>
                {result().text}
              </div>
            )}
          </Show>
        </div>
        </Show>

        <Show when={!isDirectoryKind()}>
          <div class="field">
            <label>{request().kind === "network_access" ? "Destinations requested" : "Tools requested"}</label>
            <div class="request-path mono">{request().description}</div>
            <Show when={request().kind === "network_access"}>
              <span class="hint">
                Allowing adds these to <strong>this project's</strong> allowlist only. A DENY entry in the
                global list still wins, so a host banned app-wide cannot be opened here.
              </span>
            </Show>
            <Show when={request().kind === "tool_install"}>
              <span class="hint">
                A tool is baked into the project's image, so it is not usable until the image is rebuilt
                and the sandbox restarted. DeepCode is told this, so it will not try to install it itself.
              </span>
            </Show>
          </div>
        </Show>

        <Show when={isDirectoryKind()}>
        <div class="field">
          <label>Access to grant</label>
          <div class="access-choice">
            <button
              class="access-option"
              aria-pressed={access() === "read"}
              onClick={() => setAccess("read")}
            >
              <strong>Read-only</strong>
              <span>It can read the files but cannot change or delete anything.</span>
            </button>
            <button
              class="access-option"
              aria-pressed={access() === "write"}
              onClick={() => setAccess("write")}
            >
              <strong>Read-write</strong>
              <span>It can create, modify and delete files in this directory.</span>
            </button>
          </div>
        </div>
        </Show>

        <div class="field">
          <label for="perm-note">Reply to DeepCode (optional)</label>
          <input
            id="perm-note"
            type="text"
            placeholder="Only the theme folder, please"
            value={note()}
            onInput={(event) => setNote(event.currentTarget.value)}
          />
        </div>

        <div class="callout callout-info">
          Approving recreates this project's container so the new mount can be attached, then resumes the session.
          Denying is final: DeepCode is told not to retry and that no workaround exists.
        </div>
      </div>
    </Modal>
  );
}

/* ------------------------------------------------------------------------- */
/* New project                                                                */
/* ------------------------------------------------------------------------- */

export function NewProjectDialog(props: { onClose: () => void }) {
  const [name, setName] = createSignal("");
  const [root, setRoot] = createSignal("");
  const [busy, setBusy] = createSignal(false);
  const [check, setCheck] = createSignal<{ ok: boolean; text: string } | null>(null);

  async function verify(candidate: string) {
    if (!candidate.trim()) {
      setCheck(null);
      return;
    }
    try {
      const result = await api.pathCheck(candidate);
      setCheck(
        result.allowed
          ? { ok: true, text: `Usable. It becomes /workspace inside the sandbox.` }
          : { ok: false, text: result.reason ?? "This directory cannot be used." },
      );
    } catch (error) {
      setCheck({ ok: false, text: describeError(error) });
    }
  }

  async function browse() {
    const chosen = await open({ directory: true, multiple: false, title: "Choose the working directory" });
    if (typeof chosen === "string") {
      setRoot(chosen);
      await verify(chosen);
    }
  }

  async function create() {
    setBusy(true);
    try {
      const project = await api.createProject(name(), root());
      await refreshProjects();
      toast("ok", `Created ${project.name}`, "Run it when you are ready.");
      props.onClose();
    } catch (error) {
      toast("error", "Could not create the project", describeError(error));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal
      title="New project"
      subtitle="A project is a working directory plus the permissions DeepCode has inside it."
      onClose={props.onClose}
      footer={
        <>
          <button class="btn btn-ghost" onClick={props.onClose}>
            Cancel
          </button>
          <button
            class="btn btn-primary"
            disabled={busy() || !name().trim() || !root().trim() || check()?.ok === false}
            onClick={() => void create()}
          >
            Create project
          </button>
        </>
      }
    >
      <div class="stack">
        <div class="field">
          <label for="np-name">Name</label>
          <input
            id="np-name"
            type="text"
            placeholder="my-website"
            value={name()}
            onInput={(event) => setName(event.currentTarget.value)}
          />
        </div>
        <div class="field">
          <label for="np-root">Primary working directory</label>
          <div class="row-inline">
            <input
              id="np-root"
              class="grow"
              type="text"
              placeholder="D:\work\my-website"
              value={root()}
              onInput={(event) => setRoot(event.currentTarget.value)}
              onChange={(event) => void verify(event.currentTarget.value)}
            />
            <button class="btn" onClick={() => void browse()}>
              Browse…
            </button>
          </div>
          <Show when={check()}>
            {(result) => (
              <div class={result().ok ? "callout callout-info" : "callout callout-danger"}>
                {result().text}
              </div>
            )}
          </Show>
        </div>
        <div class="callout callout-info">
          The sandbox sees this directory at <span class="mono">/workspace</span>. It sees nothing else until you
          share something — not your home folder, not your other projects, and never a container-runtime socket.
        </div>
      </div>
    </Modal>
  );
}

/* ------------------------------------------------------------------------- */
/* Project settings                                                           */
/* ------------------------------------------------------------------------- */

export function ProjectSettingsDialog(props: { project: ProjectView; onClose: () => void }) {
  const [mode, setMode] = createSignal(props.project.deepcodeMode);
  const [limits, setLimits] = createSignal<ResourceLimits>({ ...DEFAULT_LIMITS, ...props.project.limits });
  const [model, setModel] = createSignal(props.project.credentials.model ?? "");
  const [baseUrl, setBaseUrl] = createSignal(props.project.credentials.base_url ?? "");
  const [apiKey, setApiKey] = createSignal("");
  const [inherit, setInherit] = createSignal(props.project.credentials.source !== "project");
  const [busy, setBusy] = createSignal(false);

  async function save() {
    setBusy(true);
    try {
      await api.updateProjectSettings({
        projectId: props.project.id,
        deepcodeMode: mode(),
        limits: limits(),
        credentials: inherit()
          ? { source: "inherit_host" }
          : {
              source: "project",
              model: model() || null,
              base_url: baseUrl() || null,
              api_key: apiKey() || props.project.credentials.api_key || null,
            },
      });
      await refreshProjects();
      toast("ok", "Project settings saved", "They apply the next time the sandbox starts.");
      props.onClose();
    } catch (error) {
      toast("error", "Could not save", describeError(error));
    } finally {
      setBusy(false);
    }
  }

  async function remove() {
    setBusy(true);
    try {
      await api.deleteProject(props.project.id);
      await refreshProjects();
      toast("info", `Removed ${props.project.name}`);
      props.onClose();
    } catch (error) {
      toast("error", "Could not remove the project", describeError(error));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal
      title={`${props.project.name} settings`}
      subtitle={props.project.rootDir}
      wide
      onClose={props.onClose}
      footer={
        <>
          <button class="btn btn-danger left" disabled={busy()} onClick={() => void remove()}>
            Remove project
          </button>
          <button class="btn btn-ghost" onClick={props.onClose}>
            Cancel
          </button>
          <button class="btn btn-primary" disabled={busy()} onClick={() => void save()}>
            Save
          </button>
        </>
      }
    >
      <div class="stack">
        <div class="field">
          <label>DeepCode's own permission prompts inside the sandbox</label>
          <div class="row-inline">
            <button
              class="btn btn-sm"
              aria-pressed={mode() === "allow_all"}
              style={
                mode() === "allow_all"
                  ? { "border-color": "var(--accent)", background: "var(--accent-soft)" }
                  : undefined
              }
              onClick={() => setMode("allow_all")}
            >
              Quiet (recommended)
            </button>
            <button
              class="btn btn-sm"
              aria-pressed={mode() === "strict"}
              style={
                mode() === "strict"
                  ? { "border-color": "var(--accent)", background: "var(--accent-soft)" }
                  : undefined
              }
              onClick={() => setMode("strict")}
            >
              Strict
            </button>
          </div>
          <span class="hint">
            The container is the real boundary. Strict mode additionally makes DeepCode prompt for network, MCP and
            out-of-workspace access, with the prompts appearing in the terminal.
          </span>
        </div>

        <div class="field">
          <label>Model credentials</label>
          <div class="row-inline">
            <button
              class="btn btn-sm"
              aria-pressed={inherit()}
              style={
                inherit() ? { "border-color": "var(--accent)", background: "var(--accent-soft)" } : undefined
              }
              onClick={() => setInherit(true)}
            >
              Inherit from this machine
            </button>
            <button
              class="btn btn-sm"
              aria-pressed={!inherit()}
              style={!inherit() ? { "border-color": "var(--accent)", background: "var(--accent-soft)" } : undefined}
              onClick={() => setInherit(false)}
            >
              Override for this project
            </button>
          </div>
          <Show when={inherit()}>
            <span class="hint">
              Reads <span class="mono">{store.info?.hostConfig.path}</span> at every start. Model:{" "}
              <span class="mono">{store.info?.hostConfig.model}</span>, key{" "}
              <span class="mono">{store.info?.hostConfig.apiKey}</span>.
            </span>
          </Show>
          <Show when={!inherit()}>
            <div class="stack" style={{ "margin-top": "0.5rem" }}>
              <input
                type="text"
                placeholder="model, e.g. deepseek-v4-flash"
                value={model()}
                onInput={(event) => setModel(event.currentTarget.value)}
              />
              <input
                type="text"
                placeholder="base URL, e.g. https://api.deepseek.com"
                value={baseUrl()}
                onInput={(event) => setBaseUrl(event.currentTarget.value)}
              />
              <input
                type="password"
                placeholder="API key (leave blank to keep the current one)"
                value={apiKey()}
                onInput={(event) => setApiKey(event.currentTarget.value)}
              />
            </div>
          </Show>
        </div>

        <div class="field">
          <label>Resource limits</label>
          <div class="row-inline" style={{ "flex-wrap": "wrap" }}>
            <label class="small muted">
              Memory (MiB)
              <input
                type="number"
                min="256"
                value={limits().memory_mb}
                onInput={(event) =>
                  setLimits({ ...limits(), memory_mb: Number(event.currentTarget.value) || 0 })
                }
              />
            </label>
            <label class="small muted">
              CPUs
              <input
                type="number"
                min="0.25"
                step="0.25"
                value={limits().cpus}
                onInput={(event) => setLimits({ ...limits(), cpus: Number(event.currentTarget.value) || 1 })}
              />
            </label>
            <label class="small muted">
              Processes
              <input
                type="number"
                min="32"
                value={limits().pids_limit}
                onInput={(event) =>
                  setLimits({ ...limits(), pids_limit: Number(event.currentTarget.value) || 128 })
                }
              />
            </label>
            <label class="small muted">
              /tmp (MiB)
              <input
                type="number"
                min="64"
                value={limits().tmpfs_mb}
                onInput={(event) => setLimits({ ...limits(), tmpfs_mb: Number(event.currentTarget.value) || 256 })}
              />
            </label>
          </div>
        </div>
      </div>
    </Modal>
  );
}

/* ------------------------------------------------------------------------- */
/* Global settings                                                            */
/* ------------------------------------------------------------------------- */

/* ------------------------------------------------------------------------- */
/* Remote access                                                             */
/* ------------------------------------------------------------------------- */

/**
 * The whole remote access section, including the feature toggle that hides it.
 *
 * Saves immediately rather than through the dialog's Save button, because starting
 * and stopping listeners is a side effect the operator expects to happen when they
 * press the button, not when they later close a form.
 */
/**
 * The start-with-the-computer control.
 *
 * The switch reflects the operating system, not the settings file: if the entry is removed by
 * hand the control follows, rather than claiming to be on.
 *
 * Three options rather than a checkbox, because "start with the computer" and "start with the
 * computer and take over the screen" are different intentions. Background is the one that needs
 * the tray icon, which the app puts in place by itself.
 */
function AutostartSection() {
  const [mode, setMode] = createSignal<StartupMode | null>(null);
  const [busy, setBusy] = createSignal(false);
  const [problem, setProblem] = createSignal<string | null>(null);

  onMount(() => {
    void api
      .getStartupMode()
      .then((value) => setMode(value))
      .catch(() => setMode(null));
  });

  async function choose(next: StartupMode) {
    const previous = mode();
    setBusy(true);
    setProblem(null);
    setMode(next);
    try {
      setMode(await api.setStartupMode(next));
    } catch (error) {
      setMode(previous);
      setProblem(describeError(error));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div class="field">
      <label>Starting up</label>
      <div class="row-inline">
        <span class="grow">
          Start Deepsand when I sign in.
          <span class="hint">
            In the background it starts with no window at all — the tray icon opens it, and it is
            running so your sandboxes can be.
          </span>
        </span>
        <select
          class="select-compact"
          value={mode() ?? "off"}
          disabled={busy() || mode() === null}
          onChange={(event) => void choose(event.currentTarget.value as StartupMode)}
        >
          <option value="off">Off</option>
          <option value="background">In the background</option>
          <option value="foreground">With the window</option>
        </select>
      </div>
      <Show when={mode() === null}>
        <span class="hint">
          The startup state could not be read on this system, so it cannot be changed from here.
        </span>
      </Show>
      <Show when={problem()}>
        {(message) => <div class="callout callout-danger">{message()}</div>}
      </Show>
      <span class="hint">
        Sandboxes still only start when you run them; a project set to run on its own is not
        affected by this.
      </span>
    </div>
  );
}

function RemoteAccessSection() {
  const [view, setView] = createSignal<RemoteAccessView | null>(null);
  const [draft, setDraft] = createSignal<RemoteAccessSettings | null>(null);
  const [busy, setBusy] = createSignal(false);
  const [revealed, setRevealed] = createSignal<Record<string, boolean>>({});
  const [error, setError] = createSignal<string | null>(null);

  onMount(() => void load());

  async function load() {
    try {
      const loaded = await api.getRemoteAccess();
      setView(loaded);
      setDraft({
        enabled: loaded.enabled,
        persistAcrossRestarts: loaded.persistAcrossRestarts,
        lockoutAfterFailures: loaded.lockoutAfterFailures,
        servers: loaded.servers.map((server) => ({
          id: server.id,
          label: server.label,
          scope:
            server.scopeKind === "project" && server.projectId
              ? { kind: "project" as const, projectId: server.projectId }
              : { kind: "app" as const },
          bind: server.bind,
          port: server.port,
          tls: server.tls,
          capabilities: { ...server.capabilities },
          token: server.token,
        })),
      });
    } catch (caught) {
      setError(describeError(caught));
    }
  }

  function edit(change: (current: RemoteAccessSettings) => RemoteAccessSettings) {
    const current = draft();
    if (current) setDraft(change(current));
  }

  function patchServer(id: string, change: (server: RemoteServerConfig) => RemoteServerConfig) {
    edit((current) => ({
      ...current,
      servers: current.servers.map((server) => (server.id === id ? change(server) : server)),
    }));
  }

  function addServer() {
    edit((current) => ({
      ...current,
      servers: [
        ...current.servers,
        {
          // The backend only needs an id that is stable; it does not have to be a
          // uuid, and the token is generated server-side when this is saved.
          id: `srv-${Date.now().toString(36)}`,
          label: current.servers.length === 0 ? "Remote access" : `Server ${current.servers.length + 1}`,
          scope: selectedProject() ? { kind: "project", projectId: selectedProject()!.id } : { kind: "app" },
          bind: "127.0.0.1",
          port: 47821 + current.servers.length,
          tls: "off",
          capabilities: {
            control: true,
            grantPermissions: false,
            manageProjects: false,
            changeSecurity: false,
          },
          token: "",
        },
      ],
    }));
  }

  async function apply() {
    const current = draft();
    if (!current) return;
    setBusy(true);
    setError(null);
    try {
      const saved = await api.setRemoteAccess(current);
      setView(saved);
      setDraft({
        ...current,
        servers: saved.servers.map((server) => ({ ...current.servers.find((s) => s.id === server.id)!, token: server.token })),
      });
      toast(
        "ok",
        current.enabled ? "Remote access updated" : "Remote access off",
        current.enabled
          ? `${saved.servers.filter((server) => server.running).length} of ${saved.servers.length} servers listening.`
          : "Every listener was stopped.",
      );
    } catch (caught) {
      // The backend refuses rather than silently downgrading, for example when TLS
      // was requested but is not implemented.
      setError(describeError(caught));
    } finally {
      setBusy(false);
    }
  }

  async function copyToken(token: string) {
    try {
      await navigator.clipboard.writeText(token);
      toast("ok", "Token copied", "Treat it like a password.");
    } catch {
      toast("error", "Could not copy", "Select the token and copy it manually.");
    }
  }

  return (
    <div class="field">
      <label>Remote access</label>
      <span class="hint">
        Serve this GUI over HTTP so another device can reach it. Off by default, and the settings
        below only appear when it is on.
      </span>

      <Show when={draft()} fallback={<span class="hint">Loading…</span>}>
        {(current) => (
          <>
            <label class="row-inline small" style={{ "margin-top": "0.5rem" }}>
              <input
                type="checkbox"
                checked={current().enabled}
                onChange={(event) =>
                  edit((state) => ({ ...state, enabled: event.currentTarget.checked }))
                }
              />
              Enable remote access
            </label>

            <Show when={current().enabled}>
              <label class="row-inline small">
                <input
                  type="checkbox"
                  checked={current().persistAcrossRestarts}
                  onChange={(event) =>
                    edit((state) => ({ ...state, persistAcrossRestarts: event.currentTarget.checked }))
                  }
                />
                Keep servers running across restarts
              </label>
              <span class="hint">
                Left off, the port closes when Deepsand exits. That is the safer default: a window
                opened for one afternoon should not still be open next month.
              </span>

              <label class="row-inline small" style={{ "margin-top": "0.5rem" }}>
                Lock out an address after
                <input
                  type="number"
                  min={0}
                  style={{ width: "4rem" }}
                  aria-label="Failed attempts before lockout"
                  value={current().lockoutAfterFailures}
                  onInput={(event) =>
                    edit((state) => ({
                      ...state,
                      lockoutAfterFailures: Math.max(0, Number(event.currentTarget.value) || 0),
                    }))
                  }
                />
                failed attempts
              </label>
              <span class="hint">
                A locked-out address gets a "try again shortly" for five minutes; a correct token
                clears the count. Zero disables the limit, which is reasonable on a loopback-only
                server where the token is a formality.
              </span>

              <div class="callout callout-warn" style={{ "margin-top": "0.7rem" }}>
                Plain HTTP, so the access token crosses the network in clear text. Bind to{" "}
                <span class="mono">127.0.0.1</span> and put a reverse proxy in front for TLS and real
                authentication; that is also why every server defaults to loopback.
              </div>

              <For each={current().servers}>
                {(server) => {
                  const status = () => view()?.servers.find((candidate) => candidate.id === server.id);
                  return (
                    <div class="card" style={{ "margin-top": "0.7rem" }}>
                      <div class="row-inline" style={{ "justify-content": "space-between" }}>
                        <input
                          value={server.label}
                          aria-label="Server label"
                          onInput={(event) => patchServer(server.id, (s) => ({ ...s, label: event.currentTarget.value }))}
                        />
                        <button
                          class="btn btn-sm btn-ghost"
                          onClick={() =>
                            edit((state) => ({
                              ...state,
                              servers: state.servers.filter((candidate) => candidate.id !== server.id),
                            }))
                          }
                        >
                          Remove
                        </button>
                      </div>

                      <div class="row-inline" style={{ "margin-top": "0.4rem", "flex-wrap": "wrap" }}>
                        <span class="small muted">
                          {status()?.running
                            ? `Listening on ${status()?.boundAddr}`
                            : current().enabled
                              ? "Not listening"
                              : "Stopped"}
                        </span>
                        <span class="mono small">{status()?.displayUrl ?? ""}</span>
                        <Show when={!status()?.loopbackOnly}>
                          <span class="small" style={{ color: "var(--danger)" }}>
                            Reachable from the network
                          </span>
                        </Show>
                      </div>

                      <div class="row-inline" style={{ "margin-top": "0.5rem", "flex-wrap": "wrap" }}>
                        <label class="small">
                          Scope
                          <select
                            value={server.scope.kind === "project" ? server.scope.projectId : ""}
                            onChange={(event) => {
                              const value = event.currentTarget.value;
                              patchServer(server.id, (s) => ({
                                ...s,
                                scope: value ? { kind: "project", projectId: value } : { kind: "app" },
                              }));
                            }}
                          >
                            <option value="">Every project</option>
                            <For each={store.projects}>
                              {(project) => <option value={project.id}>{project.name} only</option>}
                            </For>
                          </select>
                        </label>
                        <label class="small">
                          Bind
                          <input
                            value={server.bind}
                            aria-label="Bind address"
                            onInput={(event) => patchServer(server.id, (s) => ({ ...s, bind: event.currentTarget.value }))}
                          />
                        </label>
                        <label class="small">
                          Port
                          <input
                            type="number"
                            value={server.port}
                            aria-label="Port"
                            onInput={(event) =>
                              patchServer(server.id, (s) => ({ ...s, port: Number(event.currentTarget.value) || 0 }))
                            }
                          />
                        </label>
                        <label class="small">
                          TLS
                          <select
                            value={server.tls}
                            onChange={(event) =>
                              patchServer(server.id, (s) => ({
                                ...s,
                                tls: event.currentTarget.value === "selfSigned" ? "selfSigned" : "off",
                              }))
                            }
                          >
                            <option value="off">Off (behind a proxy)</option>
                            <option value="selfSigned">Self-signed</option>
                          </select>
                        </label>
                      </div>

                      <div class="small" style={{ "margin-top": "0.5rem" }}>
                        <strong>What this client may do</strong>
                        <label class="row-inline small">
                          <input
                            type="checkbox"
                            checked={server.capabilities.control}
                            onChange={(event) =>
                              patchServer(server.id, (s) => ({
                                ...s,
                                capabilities: { ...s.capabilities, control: event.currentTarget.checked },
                              }))
                            }
                          />
                          Run and stop sandboxes, type into the terminal
                        </label>
                        <label class="row-inline small">
                          <input
                            type="checkbox"
                            checked={server.capabilities.grantPermissions}
                            onChange={(event) =>
                              patchServer(server.id, (s) => ({
                                ...s,
                                capabilities: { ...s.capabilities, grantPermissions: event.currentTarget.checked },
                              }))
                            }
                          />
                          Grant permissions: answer requests, mount directories, edit allowlists
                        </label>
                        <label class="row-inline small">
                          <input
                            type="checkbox"
                            checked={server.capabilities.manageProjects}
                            onChange={(event) =>
                              patchServer(server.id, (s) => ({
                                ...s,
                                capabilities: { ...s.capabilities, manageProjects: event.currentTarget.checked },
                              }))
                            }
                          />
                          Create and delete projects
                        </label>
                        <label class="row-inline small">
                          <input
                            type="checkbox"
                            checked={server.capabilities.changeSecurity}
                            onChange={(event) =>
                              patchServer(server.id, (s) => ({
                                ...s,
                                capabilities: { ...s.capabilities, changeSecurity: event.currentTarget.checked },
                              }))
                            }
                          />
                          Change security settings
                        </label>
                        <span class="hint">
                          Granting permissions is what widens the sandbox boundary, so it is separate
                          from simply driving an existing one.
                        </span>
                      </div>

                      <div class="field" style={{ "margin-top": "0.5rem" }}>
                        <label for={`token-${server.id}`}>Access token</label>
                        <div class="row-inline">
                          <input
                            id={`token-${server.id}`}
                            class="mono"
                            readonly
                            value={revealed()[server.id] ? server.token : status()?.redactedToken ?? "••••"}
                          />
                          <button
                            class="btn btn-sm"
                            onClick={() =>
                              setRevealed((state) => ({ ...state, [server.id]: !state[server.id] }))
                            }
                          >
                            {revealed()[server.id] ? "Hide" : "Reveal"}
                          </button>
                          <button class="btn btn-sm" onClick={() => void copyToken(server.token)}>
                            Copy
                          </button>
                          <button
                            class="btn btn-sm"
                            title="Issues a new token. Anything using the old one is cut off."
                            onClick={() =>
                              patchServer(server.id, (s) => ({ ...s, token: generateTokenPlaceholder() }))
                            }
                          >
                            Regenerate
                          </button>
                        </div>
                        <span class="hint">
                          Changing or regenerating a token takes effect when you apply, and cuts off
                          anything still using the old one.
                        </span>
                      </div>
                    </div>
                  );
                }}
              </For>

              <div class="row-inline" style={{ "margin-top": "0.6rem" }}>
                <button class="btn btn-sm" onClick={addServer}>
                  Add a server
                </button>
                <button class="btn btn-primary btn-sm" disabled={busy()} onClick={() => void apply()}>
                  {busy() ? "Applying…" : "Apply remote access"}
                </button>
              </div>

              <Show when={error()}>
                {(message) => (
                  <div class="callout callout-danger" style={{ "margin-top": "0.5rem" }}>
                    {message()}
                  </div>
                )}
              </Show>

              <Show when={view() && !view()!.uiDir}>
                <div class="callout callout-warn" style={{ "margin-top": "0.5rem" }}>
                  The built frontend was not found, so the servers will answer the API but have no UI
                  to serve. Run <span class="mono">npm run build</span> and rebuild the app.
                </div>
              </Show>
            </Show>
          </>
        )}
      </Show>
    </div>
  );
}

/**
 * The backend generates the real token when the settings are saved; this only has
 * to make the field visibly different so the operator can see the change took.
 */
function generateTokenPlaceholder(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

export function SettingsDialog(props: { settings: AppSettings; onClose: () => void }) {
  const [draft, setDraft] = createSignal<AppSettings>({ ...props.settings });
  const [allowlist, setAllowlist] = createSignal(props.settings.egress_allowlist.join("\n"));
  // The app settings dialog has no save to be busy with; the controls still read this.
  const [busy] = createSignal(false);
  const [updateCheck, setUpdateCheck] = createSignal<UpdateCheck | null>(null);
  const [updateBusy, setUpdateBusy] = createSignal(false);
  const [installing, setInstalling] = createSignal(false);
  const [progress, setProgress] = createSignal<UpdateProgress | null>(null);

  /**
   * Ask what version is out there.
   *
   * Run when the dialog opens rather than only from the button, because the answer is
   * what this section is for. A failed check is shown as itself rather than as "up to
   * date": a laptop on a train is not the same thing as a current install.
   */
  async function toggleCloseToTray(enabled: boolean) {
    const previous = draft().close_to_tray;
    setDraft({ ...draft(), close_to_tray: enabled });
    try {
      await api.setCloseToTray(enabled);
      await refreshSettings();
    } catch (error) {
      setDraft({ ...draft(), close_to_tray: previous });
      toast("error", "Could not change the closing behaviour", describeError(error));
    }
  }

  /** The last tool-version check this dialog asked for, if any. */
  const [toolBusy, setToolBusy] = createSignal(false);
  const [toolReport, setToolReport] = createSignal<string[] | null>(null);

  async function checkToolsNow() {
    setToolBusy(true);
    try {
      const notes = await api.checkToolUpdatesNow();
      setToolReport(notes);
      toast(
        notes.length ? "info" : "ok",
        notes.length ? "Cached tools have moved on" : "Cached tools are current",
        notes.join(" ") ||
          "Nothing in the cache has a newer version published.",
      );
    } catch (error) {
      toast("error", "Could not check the cached tools", describeError(error));
    } finally {
      setToolBusy(false);
    }
  }

  async function checkUpdates() {
    setUpdateBusy(true);
    try {
      setUpdateCheck(await api.checkForUpdates());
    } catch (error) {
      setUpdateCheck({
        currentVersion: store.info?.version ?? "unknown",
        update: null,
        error: describeError(error),
      });
    } finally {
      setUpdateBusy(false);
    }
  }

  /**
   * Download and install, after which Rust restarts the app.
   *
   * This does not come back on success -- the process is replaced -- so the busy state is
   * deliberately not reset in a `finally`: it would only flicker on the way out.
   */
  async function install() {
    if (installing()) return;
    setInstalling(true);
    setProgress(null);
    try {
      await api.installUpdate();
    } catch (error) {
      toast("error", "Could not install the update", describeError(error));
      setInstalling(false);
      setProgress(null);
    }
  }

  onMount(() => {
    void checkUpdates();
    const unlisten = api.onUpdateProgress(setProgress);
    onCleanup(() => void unlisten.then((off) => off()).catch(() => undefined));
  });

  /** Sandboxes an installer would take down with the app. */
  const runningCount = () => store.projects.filter((project) => project.running).length;

  const downloadLine = () => {
    const current = progress();
    if (!current) return "";
    if (current.phase === "installing") return "Downloaded. Installing…";
    const mb = (bytes: number) => (bytes / (1024 * 1024)).toFixed(1);
    return current.total
      ? `Downloading… ${mb(current.downloaded)} of ${mb(current.total)} MB`
      : `Downloading… ${mb(current.downloaded)} MB`;
  };

  /** Which entries were dropped as unparseable, so the hint can say so rather than be silent. */
  const [ignored, setIgnored] = createSignal(0);
  const [saving, setSaving] = createSignal(false);
  const [saved, setSaved] = createSignal(false);

  /**
   * The entries an operator typed, without the ones that cannot be an address or a name.
   *
   * A typo used to reach the backend and come back as a failed save, which is a bad way to learn
   * about a stray character: the rest of the list was fine and none of it was saved. Dropping what
   * cannot be an entry keeps the ones that can, which is what somebody editing a list expects.
   */
  function validHosts(text: string): { hosts: string[]; dropped: number } {
    const lines = text
      .split(/[\n,]/)
      .map((line) => line.trim())
      .filter(Boolean);
    const hosts = lines.filter((line) =>
      /^(\*|\*\.)?[a-z0-9._-]+(:\d{1,5})?$/i.test(line) || /^\[[0-9a-f:]+\](:\d{1,5})?$/i.test(line),
    );
    return { hosts, dropped: lines.length - hosts.length };
  }

  let settled = false;
  let timer: number | undefined;

  /**
   * Save as the operator types.
   *
   * Debounced, because a text area fires on every keystroke and each save rewrites the state file
   * and pushes the settings into any running sandbox. The first run is skipped: opening the dialog
   * is not an edit, and a save on open would rewrite a file nobody changed.
   */
  createEffect(() => {
    const settings = draft();
    const text = allowlist();
    if (!settled) {
      settled = true;
      return;
    }
    window.clearTimeout(timer);
    timer = window.setTimeout(() => void autosave(settings, text), 700);
  });

  onCleanup(() => window.clearTimeout(timer));

  async function autosave(settings: AppSettings, text: string) {
    setSaving(true);
    try {
      const { hosts, dropped } = validHosts(text);
      const cleaned = await api.setEgressAllowlist(hosts);
      await api.setSettings({ ...settings, egress_allowlist: cleaned });
      await refreshSettings();
      setIgnored(dropped);
      setSaved(true);
    } catch (error) {
      toast("error", "Could not save settings", describeError(error));
      setSaved(false);
    } finally {
      setSaving(false);
    }
  }

  async function buildImage() {
    try {
      await api.buildRuntimeImage(false);
      toast("info", "Building the runtime image", "Watch progress in the Activity tab.");
    } catch (error) {
      toast("error", "Could not start the build", describeError(error));
    }
    props.onClose();
  }

  return (
    <Modal
      title="Settings"
      onClose={props.onClose}
      wide
      footer={
        <>
          <span class="left">Data: {store.info?.dataDir}</span>
          <button class="btn btn-ghost" onClick={props.onClose}>
            Cancel
          </button>
          <span class="hint">
            {saving() ? "Saving…" : saved() ? "Saved" : ""}
            {ignored() > 0 ? ` — ${ignored()} entr${ignored() === 1 ? "y" : "ies"} ignored` : ""}
          </span>
        </>
      }
    >
      <div class="stack">
        <div class="field">
          <label for="set-image">Runtime image</label>
          <div class="row-inline">
            <input
              id="set-image"
              class="grow"
              type="text"
              value={draft().image}
              onInput={(event) => setDraft({ ...draft(), image: event.currentTarget.value })}
            />
            <button class="btn" onClick={() => void buildImage()}>
              Build now
            </button>
          </div>
          <span class="hint">
            Built from <span class="mono">runtime/Dockerfile</span>.{" "}
            <Show
              when={store.info?.docker}
              fallback={<span class="badge">checking…</span>}
            >
              {(docker) => (
                <Show
                  when={docker().image_present}
                  fallback={<span class="badge badge-warn">not built yet</span>}
                >
                  <span class="badge badge-ok">present</span>
                </Show>
              )}
            </Show>
          </span>
        </div>

        <div class="field">
          <label>Network for new projects</label>
          <NetworkSlider
            value={draft().default_network.mode}
            disabled={busy()}
            onChange={(mode) =>
              setDraft({
                ...draft(),
                // `allowlisted` carries a list; a project starts with an empty one and inherits
                // the global entries, so the field is not a second place to maintain the
                // allowlist.
                default_network: mode === "allowlisted" ? { mode, allow: [] } : { mode },
              })
            }
          />
          <span class="hint">
            The mode every project you create from now on starts in. <strong>Allowlisted</strong> is
            the default and means default-deny: the model endpoint, the package registries in the
            global list, and whatever a project's tools need. Existing projects keep the mode they
            already have.
          </span>
          <Show when={draft().default_network.mode === "full"}>
            <div class="callout callout-warn">
              Full egress removes the local-network block as well as the allowlist. Only choose this
              if the sandbox genuinely needs to reach machines on your own network.
            </div>
          </Show>
        </div>

        <div class="field">
          <label>Default credentials</label>
          <div class="row-inline">
            <input
              class="grow"
              type="text"
              placeholder="deepseek-v4-flash"
              value={draft().default_model}
              onInput={(event) => setDraft({ ...draft(), default_model: event.currentTarget.value })}
            />
            <input
              class="grow"
              type="text"
              placeholder="https://api.deepseek.com"
              value={draft().default_base_url}
              onInput={(event) => setDraft({ ...draft(), default_base_url: event.currentTarget.value })}
            />
          </div>
          <span class="hint">
            Used only when the host configuration and the project both say nothing. API keys are never stored here;
            they come from <span class="mono">{store.info?.hostConfig.path}</span> or a project override.
          </span>
        </div>

        <div class="field">
          <label for="set-allow">Egress allowlist (one host per line)</label>
          <textarea
            id="set-allow"
            value={allowlist()}
            onInput={(event) => setAllowlist(event.currentTarget.value)}
          />
          <span class="hint">
            Only used by the allowlisted network mode. A blanket <span class="mono">*</span> is ignored: use{" "}
            <span class="mono">*.example.com</span> to include subdomains. Ports 80 and 443 only.
          </span>
        </div>

        <div class="field">
          <label>Behaviour</label>
          <label class="row-inline small">
            <input
              type="checkbox"
              checked={draft().auto_restart_on_grant}
              onChange={(event) =>
                setDraft({ ...draft(), auto_restart_on_grant: event.currentTarget.checked })
              }
            />
            Restart the sandbox automatically when a permission is granted
          </label>
        </div>

        <AutostartSection />

        <RemoteAccessSection />

        <div class="field">
          <label>Hardening</label>
          <label class="row-inline small">
            <input
              type="checkbox"
              checked={draft().security.read_only_rootfs}
              onChange={(event) =>
                setDraft({
                  ...draft(),
                  security: { ...draft().security, read_only_rootfs: event.currentTarget.checked },
                })
              }
            />
            Read-only container filesystem
          </label>
          <label class="row-inline small">
            <input
              type="checkbox"
              checked={draft().security.no_new_privileges}
              onChange={(event) =>
                setDraft({
                  ...draft(),
                  security: { ...draft().security, no_new_privileges: event.currentTarget.checked },
                })
              }
            />
            Block privilege escalation inside the container
          </label>
          <label class="row-inline small">
            <input
              type="checkbox"
              checked={draft().security.netfilter_required}
              onChange={(event) =>
                setDraft({
                  ...draft(),
                  security: { ...draft().security, netfilter_required: event.currentTarget.checked },
                })
              }
            />
            Refuse to start if the network policy cannot be enforced
          </label>
          <label class="row-inline small">
            <input
              type="checkbox"
              checked={draft().security.seccomp === "hardened"}
              onChange={(event) =>
                setDraft({
                  ...draft(),
                  security: {
                    ...draft().security,
                    seccomp: event.currentTarget.checked ? "hardened" : "default",
                  },
                })
              }
            />
            Use Deepsand's hardened seccomp profile
          </label>
          <span class="hint">
            Docker Desktop runs the daemon inside a VM, so the hardened profile and AppArmor cannot be applied
            there. Deepsand says so in the plan preview rather than pretending otherwise.
          </span>
        </div>

        <div class="field">
          <label>Closing</label>
          <label class="check">
            <input
              type="checkbox"
              checked={draft().close_to_tray}
              onChange={(event) => void toggleCloseToTray(event.currentTarget.checked)}
            />
            The close button hides Deepsand in the tray instead of stopping it
          </label>
          <span class="hint">
            Off, closing does what it has always done: the sandboxes stop and Deepsand quits. On, the
            window disappears and everything keeps running — the tray icon opens it again, and its
            Quit stops the sandboxes.
          </span>
        </div>

        <div class="field">
          <label>Updates</label>
          <div class="row-inline">
            <span class="grow">
              This build is <span class="mono">{store.info?.version ?? "unknown"}</span>.{" "}
              <Show when={updateCheck()} fallback={<span class="hint">Checking…</span>}>
                {(result) => (
                  <Show
                    when={result().update}
                    fallback={
                      <Show
                        when={result().error}
                        fallback={<span class="badge badge-ok">up to date</span>}
                      >
                        {(reason) => <span class="badge badge-warn">{reason()}</span>}
                      </Show>
                    }
                  >
                    {(available) => (
                      <span class="badge badge-warn">{available().version} is available</span>
                    )}
                  </Show>
                )}
              </Show>
            </span>
            <button class="btn" disabled={updateBusy() || installing()} onClick={() => void checkUpdates()}>
              {updateBusy() ? "Checking…" : "Check for updates"}
            </button>
          </div>

          <div class="row-inline">
            <label class="check grow">
              <input
                type="checkbox"
                checked={draft().check_tool_updates}
                onChange={(event) =>
                  setDraft({ ...draft(), check_tool_updates: event.currentTarget.checked })
                }
              />
              Check the cached tools for newer versions at startup, and every six hours
            </label>
            <button class="btn" disabled={toolBusy()} onClick={() => void checkToolsNow()}>
              {toolBusy() ? "Checking…" : "Check now"}
            </button>
          </div>
          <Show when={toolReport()}>
            {(notes) => (
              <span class="hint">
                {notes().length === 0
                  ? "Every cached tool is current."
                  : notes().join(" ")}
              </span>
            )}
          </Show>

          <Show when={updateCheck()?.update}>
            {(available) => (
              <>
                <Show when={available().notes}>
                  <span class="hint" style={{ display: "block", "white-space": "pre-wrap" }}>
                    {available().notes}
                  </span>
                </Show>
                {/* An install replaces this binary and restarts the app, which takes the
                    sandbox down with it. Said before the click, not after. */}
                <Show when={runningCount() > 0}>
                  <div class="callout callout-warn" style={{ "margin-top": "0.5rem" }}>
                    Installing restarts Deepsand, which stops{" "}
                    {runningCount() === 1 ? "the running sandbox" : `all ${runningCount()} running sandboxes`}.
                    Anything the agent has not written to disk is lost, and the session has to be started again.
                  </div>
                </Show>
                <div class="row-inline" style={{ "margin-top": "0.5rem" }}>
                  <button class="btn btn-primary" disabled={installing()} onClick={() => void install()}>
                    {installing() ? "Installing…" : `Install ${available().version} and restart`}
                  </button>
                  <Show when={downloadLine()}>
                    <span class="hint">{downloadLine()}</span>
                  </Show>
                </div>
              </>
            )}
          </Show>

          <span class="hint">
            The tool check asks npm and crates.io what they offer for the versions your cache holds,
            and empties that cache when something has moved, so the next build installs it again. It
            never builds anything by itself, and turning it off leaves the "Check now" button working.

            Updates are signed, and the signature is what Deepsand checks before installing — not the
            download. A release that is not signed with this project's key will be refused.
          </span>
        </div>
      </div>
    </Modal>
  );
}

/* ------------------------------------------------------------------------- */
/* Toasts                                                                     */
/* ------------------------------------------------------------------------- */

/**
 * Copy a box's text, in full.
 *
 * The clipboard is the point: the operator's next move after reading an error is to paste it
 * somewhere, and the box used to be gone the instant it was clicked -- which is the first
 * thing anyone does when they mean to select the text.
 */
async function copyToast(entry: { title: string; body?: string }) {
  const text = entry.body ? `${entry.title}\n\n${entry.body}` : entry.title;
  try {
    await navigator.clipboard.writeText(text);
    toast("ok", "Copied", "The message is on the clipboard.");
  } catch {
    // No clipboard permission is not a reason to lose the message: it is still selectable,
    // and it is in the log.
    toast("warn", "Could not copy", "Select the text instead; it is in the log too.");
  }
}

export function Toasts() {
  return (
    <div
      style={{
        position: "fixed",
        right: "1rem",
        bottom: "1rem",
        display: "flex",
        "flex-direction": "column",
        gap: "0.5rem",
        "z-index": 80,
        "max-width": "26rem",
      }}
    >
      <For each={store.toasts}>
        {(entry) => (
          <div
            class={`callout ${
              entry.kind === "error"
                ? "callout-danger"
                : entry.kind === "warn"
                  ? "callout-warn"
                  : "callout-info"
            }`}
            style={{
              "box-shadow": "0 10px 30px #00000090",
              background: "var(--bg-raised)",
              // An error is not dismissed by a click: a click is how you start selecting the
              // text, and losing the message that way is the complaint this answers. The
              // others still go away when clicked, which is what makes them unobtrusive.
              cursor: entry.kind === "error" ? "text" : "pointer",
            }}
            onClick={
              entry.kind === "error" ? undefined : () => dismissToast(entry.id)
            }
          >
            <div
              class="row-inline"
              style={{
                "justify-content": "space-between",
                "align-items": "flex-start",
                gap: "0.5rem",
              }}
            >
              <strong>{entry.title}</strong>
              <span class="row-inline" style={{ gap: "0.25rem", "flex-shrink": "0" }}>
                <button
                  class="btn btn-ghost btn-sm"
                  title="Copy this message"
                  onClick={(event) => {
                    event.stopPropagation();
                    void copyToast(entry);
                  }}
                >
                  Copy
                </button>
                <Show when={entry.kind === "error"}>
                  <button
                    class="btn btn-ghost btn-sm"
                    title="Dismiss"
                    onClick={(event) => {
                      event.stopPropagation();
                      dismissToast(entry.id);
                    }}
                  >
                    Close
                  </button>
                </Show>
              </span>
            </div>
            <Show when={entry.body}>
              <div
                class="small"
                style={{
                  "margin-top": "0.25rem",
                  // Shown whole, and selectable: an error truncated to fit a corner is an
                  // error that cannot be pasted into a bug report.
                  "white-space": "pre-wrap",
                  "user-select": "text",
                  "max-height": "12rem",
                  overflow: "auto",
                }}
              >
                {entry.kind === "error" ? entry.body : shortPath(entry.body ?? "", 220)}
              </div>
            </Show>
          </div>
        )}
      </For>
    </div>
  );
}

import { NetworkSlider } from "./NetworkSlider";
