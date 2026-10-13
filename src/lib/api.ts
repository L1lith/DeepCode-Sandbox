/**
 * Typed wrappers around the Tauri command surface, plus the event names.
 *
 * There is exactly one place that knows the command names, so a rename in Rust
 * breaks the build here rather than failing silently at runtime.
 */

import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import type {
  AppInfo,
  AppSettings,
  BlockedEgressView,
  Credentials,
  DecisionPayload,
  DeepCodeMode,
  DockerStatus,
  GrantView,
  NetworkPolicy,
  PathCheck,
  PermissionRequestView,
  PlanPreview,
  ProjectView,
  RejectedRequestView,
  ResourceLimits,
  SessionStatus,
  AllowlistView,
  RemoteAccessView,
  RemoteAccessSettings,
  ToolCatalogView,
  EffortView,
  SecretListView,
  UpdateCheck,
  UpdateProgress,
} from "./types";

export const EVENTS = {
  terminalOutput: "terminal://output",
  terminalExit: "terminal://exit",
  sessionStatus: "session://status",
  brokerRequest: "broker://request",
  brokerResolved: "broker://resolved",
  brokerRejected: "broker://rejected",
  buildLog: "build://log",
  buildDone: "build://done",
  buildProgress: "build://progress",
  stateChanged: "state://changed",
  egressBlocked: "egress://blocked",
  updateProgress: "update://progress",
} as const;

/* --- application --------------------------------------------------------- */

export const appInfo = () => call<AppInfo>("app_info");
export const dockerStatus = () => call<DockerStatus>("docker_status");
export const startupError = () => call<string | null>("startup_error");
export const revealDataDir = () => call<string>("reveal_data_dir");

/**
 * Record something the window showed the operator.
 *
 * Deliberately never throws: this is called while reporting a failure, and a failure to
 * report must not replace it.
 */
export async function logUiEvent(level: "error" | "warn" | "info", message: string) {
  try {
    await call<void>("log_ui_event", { level, message });
  } catch {
    /* the message is still on screen; the log is the fallback, not the other way round */
  }
}

/** Where the app writes what it says about itself. */
export const logFilePath = () => call<string>("log_file_path");
export const cleanupOrphans = () => call<string[]>("cleanup_orphans");

export const getSettings = () => call<AppSettings>("get_settings");
export const setSettings = (settings: AppSettings) => call<AppSettings>("set_settings", { settings });
export const setEgressAllowlist = (hosts: string[]) =>
  call<string[]>("set_egress_allowlist", { hosts });

/**
 * One project's allowlist, with the inherited global entries alongside it.
 *
 * Per-project rather than global on purpose: a host an agent asks for while
 * working on one project should not silently become reachable from every other.
 */
export const networkPresets = () =>
  call<{ name: string; entries: string[] }[]>("network_presets");
export const projectAllowlist = (projectId: string) =>
  call<AllowlistView>("project_allowlist", { projectId });
export const setProjectAllowlist = (projectId: string, entries: string[]) =>
  call<AllowlistView>("set_project_allowlist", { projectId, entries });
/**
 * The remote access section. Both of these are local-only: they are absent from
 * the authorization table in `deepsand-core::remote`, so a remote client cannot
 * read the tokens or change its own permissions.
 */
/**
 * The tool catalogue for a project, and the selection.
 *
 * `setProjectTools` also refreshes the running proxy, which is what makes switching
 * the search tool open or close its domains straight away rather than at the next
 * restart.
 */
/**
 * Per-project secrets.
 *
 * `setSecret` sends a value one way only: nothing that comes back contains it.
 */
/**
 * Whether the OS starts Deepsand at sign-in.
 *
 * Read from the operating system rather than from the settings file, so a startup
 * entry removed by hand is reflected instead of contradicted.
 */
export const getStartAtLogin = () => call<boolean>("get_start_at_login", {});
export const setStartAtLogin = (enabled: boolean) =>
  call<boolean>("set_start_at_login", { enabled });

export const listSecrets = (projectId: string) =>
  call<SecretListView>("list_secrets", { projectId });
export const setSecret = (projectId: string, name: string, value: string) =>
  call<SecretListView>("set_secret", { projectId, name, value });
export const deleteSecret = (projectId: string, name: string) =>
  call<SecretListView>("delete_secret", { projectId, name });

export const listTools = (projectId: string) =>
  call<ToolCatalogView>("list_tools", { projectId });
export const setProjectTools = (projectId: string, ids: string[]) =>
  call<ToolCatalogView>("set_project_tools", { projectId, ids });

/** How hard the model should think. Applied without a separate save step. */
export const getEffort = (projectId: string) => call<EffortView>("get_effort", { projectId });
export const setEffort = (projectId: string, value: string) =>
  call<EffortView>("set_effort", { projectId, value });

export const getRemoteAccess = () => call<RemoteAccessView>("get_remote_access");
export const setRemoteAccess = (settings: RemoteAccessSettings) =>
  call<RemoteAccessView>("set_remote_access", { settings });

export const hostConfigSummary = () => call<Record<string, string>>("host_config_summary");

/* --- projects ------------------------------------------------------------ */

export const listProjects = () => call<ProjectView[]>("list_projects");
export const getProject = (projectId: string) => call<ProjectView>("get_project", { projectId });
export const createProject = (name: string, rootDir: string) =>
  call<ProjectView>("create_project", { name, rootDir });
export const deleteProject = (projectId: string) => call<void>("delete_project", { projectId });

export interface ProjectUpdate {
  projectId: string;
  network?: NetworkPolicy | null;
  limits?: ResourceLimits | null;
  deepcodeMode?: DeepCodeMode | null;
  notes?: string | null;
  credentials?: Credentials | null;
}

export const updateProjectSettings = (update: ProjectUpdate) =>
  call<ProjectView>("update_project_settings", update as unknown as Record<string, unknown>);

/* --- permissions --------------------------------------------------------- */

export const listGrants = (projectId: string) => call<GrantView[]>("list_grants", { projectId });
export const addGrant = (
  projectId: string,
  hostPath: string,
  access: "read" | "write",
  label?: string,
  purpose?: string,
) => call<GrantView>("add_grant", { projectId, hostPath, access, label, purpose });
export const setGrantAccess = (projectId: string, grantId: string, access: "read" | "write") =>
  call<GrantView>("set_grant_access", { projectId, grantId, access });
export const revokeGrant = (projectId: string, grantId: string) =>
  call<void>("revoke_grant", { projectId, grantId });
export const auditLog = (projectId: string, limit = 200) =>
  call<string[]>("audit_log", { projectId, limit });
export const pathCheck = (path: string) => call<PathCheck>("path_check", { path });

/**
 * Turn permission requests on or off for one project.
 *
 * Off means the sandbox stops being able to ask, and every request that is already
 * waiting is answered with a no, so it is not just a filter on the dialog.
 */
export const setRequestsEnabled = (projectId: string, enabled: boolean) =>
  call<ProjectView>("set_requests_enabled", { projectId, enabled });

/* --- updates ------------------------------------------------------------- */

/**
 * Ask whether a newer Deepsand exists.
 *
 * The check happens in Rust rather than here: the updater plugin is deliberately not
 * exposed to the webview, because installing an update replaces the binary.
 */
export const checkForUpdates = () => call<UpdateCheck>("check_for_updates");

/** Download and install the update that `checkForUpdates` found, then restart. */
export const installUpdate = () => call<void>("install_update");

export function onUpdateProgress(handler: (payload: UpdateProgress) => void): Promise<UnlistenFn> {
  return subscribe<UpdateProgress>(EVENTS.updateProgress, (event) => handler(event.payload));
}

/* --- sessions ------------------------------------------------------------ */

export const previewPlan = (projectId: string) => call<PlanPreview>("preview_plan", { projectId });
export const sessionStatus = (projectId: string) =>
  call<SessionStatus>("session_status", { projectId });
export const startSession = (projectId: string, resume = true) =>
  call<SessionStatus>("start_session", { projectId, resume });
export const stopSession = (projectId: string) => call<void>("stop_session", { projectId });
export const restartSession = (projectId: string) => call<SessionStatus>("restart_session", { projectId });
export const writeToSession = (projectId: string, data: string) =>
  call<void>("write_to_session", { projectId, data });
export const resizeSession = (projectId: string, rows: number, cols: number) =>
  call<void>("resize_session", { projectId, rows, cols });

/* --- permission requests ------------------------------------------------- */

export const listPendingRequests = () => call<PermissionRequestView[]>("list_pending_requests");
export const answerRequest = (payload: DecisionPayload) =>
  call<boolean>("answer_request", { payload });

/* --- runtime image ------------------------------------------------------- */

export const buildRuntimeImage = (buildTools = false) =>
  call<void>("build_runtime_image", { buildTools });

/* --- events -------------------------------------------------------------- */

export interface TerminalOutput {
  projectId: string;
  data: string;
}
export interface TerminalExit {
  projectId: string;
  code: number;
}
export interface SessionStatusEvent {
  projectId: string;
  status: "running" | "stopped";
}

export function onTerminalOutput(handler: (payload: TerminalOutput) => void): Promise<UnlistenFn> {
  return subscribe<TerminalOutput>(EVENTS.terminalOutput, (event) => handler(event.payload));
}

export function onTerminalExit(handler: (payload: TerminalExit) => void): Promise<UnlistenFn> {
  return subscribe<TerminalExit>(EVENTS.terminalExit, (event) => handler(event.payload));
}

export function onSessionStatus(handler: (payload: SessionStatusEvent) => void): Promise<UnlistenFn> {
  return subscribe<SessionStatusEvent>(EVENTS.sessionStatus, (event) => handler(event.payload));
}

export function onBrokerRequest(handler: (payload: PermissionRequestView) => void): Promise<UnlistenFn> {
  return subscribe<PermissionRequestView>(EVENTS.brokerRequest, (event) => handler(event.payload));
}

export function onBrokerResolved(
  handler: (payload: { requestId: string; decision: string; reason?: string }) => void,
): Promise<UnlistenFn> {
  return subscribe<{ requestId: string; decision: string; reason?: string }>(EVENTS.brokerResolved, (event) =>
    handler(event.payload),
  );
}

export function onBrokerRejected(handler: (payload: RejectedRequestView) => void): Promise<UnlistenFn> {
  return subscribe<RejectedRequestView>(EVENTS.brokerRejected, (event) => handler(event.payload));
}

export function onBuildLog(handler: (payload: { line: string }) => void): Promise<UnlistenFn> {
  return subscribe<{ line: string }>(EVENTS.buildLog, (event) => handler(event.payload));
}

export function onBuildDone(handler: (payload: { ok: boolean; image?: string; detail?: string }) => void) {
  return subscribe<{ ok: boolean; image?: string; detail?: string }>(EVENTS.buildDone, (event) =>
    handler(event.payload),
  );
}

/**
 * How far along a runtime image build is.
 *
 * Separate from the log: the log is for reading, this is for a bar. It only fires when
 * the build reports a step, so a quiet event stream means "no measurable progress"
 * rather than "finished" -- `build://done` is what says that.
 */
export function onBuildProgress(
  handler: (payload: { image: string; step: number; total: number }) => void,
) {
  return subscribe<{ image: string; step: number; total: number }>(
    EVENTS.buildProgress,
    (event) => handler(event.payload),
  );
}

export function onStateChanged(handler: (payload: { reason: string }) => void): Promise<UnlistenFn> {
  return subscribe<{ reason: string }>(EVENTS.stateChanged, (event) => handler(event.payload));
}

export function onEgressBlocked(handler: (payload: BlockedEgressView) => void): Promise<UnlistenFn> {
  return subscribe<BlockedEgressView>(EVENTS.egressBlocked, (event) => handler(event.payload));
}


/* ------------------------------------------------------------------------- */
/* Transport                                                                 */
/* ------------------------------------------------------------------------- */

/**
 * True when this frontend was loaded by a browser rather than by Tauri's webview.
 *
 * The desktop window has `__TAURI_INTERNALS__` injected; a browser that reached
 * Deepsand's remote HTTP server does not. Everything else in this file is identical
 * in both cases, which is why the switch lives here and nowhere else.
 */
export const REMOTE = typeof window !== "undefined" && !("__TAURI_INTERNALS__" in window);

const TOKEN_KEY = "deepsand.remote.token";

/**
 * The token to authenticate with, or null on the desktop.
 *
 * A token may be handed over once in the URL *fragment*, as
 * `#token=...`. A fragment is never sent to the server and never appears in a
 * reverse proxy's access log, unlike a query parameter, so it is the safest way to
 * pass one. It is stored and then stripped from the address bar so it does not
 * linger in history or in a screenshot.
 */
export function remoteToken(): string | null {
  if (!REMOTE) return null;
  const match = /(?:^|[#&])token=([^&]+)/.exec(window.location.hash);
  if (match) {
    const token = decodeURIComponent(match[1]);
    window.localStorage.setItem(TOKEN_KEY, token);
    window.history.replaceState(null, "", window.location.pathname + window.location.search);
    return token;
  }
  return window.localStorage.getItem(TOKEN_KEY);
}

export function setRemoteToken(token: string): void {
  window.localStorage.setItem(TOKEN_KEY, token.trim());
}

export function clearRemoteToken(): void {
  window.localStorage.removeItem(TOKEN_KEY);
}

/**
 * Write a command failure into the app's log.
 *
 * Every error the window shows comes from one of these, and until now none of them left a
 * trace anywhere: the box is dismissed by a click, the webview's memory goes with the window,
 * and a command whose failure the window swallows (a status refresh, a poll) said nothing at
 * all. One line each, in the same file as everything else Deepsand says about itself.
 *
 * `log_ui_event` is excluded, because a logging call that failed would log its own failure.
 * A failure to log is never allowed to become a failure of the thing being logged.
 */
function reportCommandFailure(command: string, error: unknown) {
  if (REMOTE || command === "log_ui_event") return;
  const detail = error instanceof Error ? error.message : String(error);
  void invoke("log_ui_event", {
    level: "error",
    message: `command ${command} failed: ${detail}`,
  }).catch(() => {
    /* nothing to do: the only place to say so is the place that just failed */
  });
}

/** Invoke a command over whichever transport is available. */
async function call<T>(command: string, args?: Record<string, unknown>): Promise<T> {
  if (!REMOTE) {
    try {
      return await invoke<T>(command, args);
    } catch (error) {
      reportCommandFailure(command, error);
      throw error;
    }
  }

  const token = remoteToken();
  const response = await fetch("/api/command", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      ...(token ? { authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify({ command, args: args ?? {} }),
  });

  const text = await response.text();
  let payload: { ok?: boolean; value?: T; error?: string } = {};
  try {
    payload = text ? JSON.parse(text) : {};
  } catch {
    // A proxy or a crash can produce HTML where JSON was expected; surfacing the
    // body beats "Unexpected token <".
    throw new Error(text || `HTTP ${response.status}`);
  }
  if (!response.ok || payload.ok === false) {
    const error = new Error(payload.error ?? `HTTP ${response.status}`);
    if (!REMOTE) reportCommandFailure(command, error);
    throw error;
  }
  return payload.value as T;
}

/** Subscribe to an event over whichever transport is available. */
function subscribe<T>(
  event: string,
  handler: (event: { payload: T }) => void,
): Promise<UnlistenFn> {
  if (!REMOTE) {
    return listen<T>(event, handler);
  }

  // EventSource cannot set request headers, so the token goes in the query string
  // here and only here. That is the one place it can reach an access log, which is
  // why the intended deployment is loopback plus a proxy you control.
  const source = new EventSource(`/api/events?token=${encodeURIComponent(remoteToken() ?? "")}`);
  const listener = (message: MessageEvent) => {
    try {
      handler({ payload: JSON.parse(message.data) as T });
    } catch {
      // A malformed frame should not tear down the stream.
    }
  };
  source.addEventListener(event, listener as EventListener);

  return Promise.resolve(() => {
    source.removeEventListener(event, listener as EventListener);
    source.close();
  });
}

