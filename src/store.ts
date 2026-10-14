/**
 * Application store.
 *
 * A single reactive object holds everything the UI reads. Events from the Rust
 * side mutate it; commands read from it. Keeping the wiring in one place means
 * no component has to know how anything is fetched.
 */

import { createStore } from "solid-js/store";
import type {
  AppInfo,
  AppSettings,
  BlockedEgressView,
  GrantView,
  PermissionRequestView,
  ProjectView,
  RejectedRequestView,
} from "./lib/types";
import * as api from "./lib/api";
import { decodeBase64 } from "./lib/format";

export interface Toast {
  id: number;
  kind: "info" | "ok" | "warn" | "error";
  title: string;
  body?: string;
}

interface Store {
  ready: boolean;
  fatal: string | null;
  startupNotice: string | null;
  info: AppInfo | null;
  settings: AppSettings | null;
  projects: ProjectView[];
  selectedId: string | null;
  grants: GrantView[];
  requests: PermissionRequestView[];
  rejected: RejectedRequestView[];
  blockedEgress: BlockedEgressView[];
  audit: string[];
  buildLog: string[];
  building: boolean;
  /**
   * Bumped whenever the operator's own DeepCode settings file changes on disk.
   *
   * A counter rather than a copy of the file: the answers that depend on it -- what "Defer to
   * Config" resolves to, whether the thinking switch is deferring -- are the backend's to give,
   * and a view that has already loaded re-reads them when this moves. It exists because the app
   * used to read that file once at startup and keep showing that answer, so a model changed in
   * the editor did not reach the window until it was restarted.
   */
  configRevision: number;
  /**
   * The project whose session is being started, restarted or stopped right now, if any.
   *
   * This lives here rather than in each button because two buttons did own a copy of it and
   * disagreed: the header's and the terminal's each had a local signal, so a run that failed
   * could leave one greyed out for good while the other was fine. One project, one answer.
   */
  sessionBusy: string | null;
  /**
   * The image being built, and how far along it is.
   *
   * `null` progress means the build has not reported a step yet, which is different
   * from zero: the bar is indeterminate in that case rather than claiming to be
   * stalled at the start.
   */
  buildImage: string | null;
  buildProgress: { step: number; total: number } | null;
  toasts: Toast[];
  /** Terminal output queued while a project is not on screen. */
  sessionErrors: Record<string, string>;
}

const [store, setStore] = createStore<Store>({
  ready: false,
  fatal: null,
  startupNotice: null,
  info: null,
  settings: null,
  projects: [],
  selectedId: null,
  grants: [],
  requests: [],
  rejected: [],
  blockedEgress: [],
  audit: [],
  buildLog: [],
  building: false,
  configRevision: 0,
  sessionBusy: null,
  buildImage: null,
  buildProgress: null,
  toasts: [],
  sessionErrors: {},
});

export { store };

let toastSeq = 0;

export function toast(kind: Toast["kind"], title: string, body?: string) {
  const id = ++toastSeq;
  setStore("toasts", (list) => [...list, { id, kind, title, body }]);
  if (kind === "error" || kind === "warn") {
    // Written down as well as shown. The box can be dismissed by a stray click and dies with
    // the window, which is how a message worth keeping went missing.
    void api.logUiEvent(kind, body ? `${title}\n${body}` : title);
  }
  if (kind !== "error") {
    window.setTimeout(() => dismissToast(id), 6000);
  }
  return id;
}

export function dismissToast(id: number) {
  setStore("toasts", (list) => list.filter((entry) => entry.id !== id));
}

/* ------------------------------------------------------------------------- */
/* Derived helpers                                                            */
/* ------------------------------------------------------------------------- */

export function selectedProject(): ProjectView | undefined {
  const id = store.selectedId;
  if (!id) return undefined;
  return store.projects.find((project) => project.id === id);
}

/** Human-readable explanation for a thrown command error. */
export function describeError(error: unknown): string {
  if (typeof error === "string") return error;
  if (error instanceof Error) return error.message;
  return String(error);
}

/* ------------------------------------------------------------------------- */
/* Loading                                                                    */
/* ------------------------------------------------------------------------- */

export async function bootstrap() {
  try {
    // In parallel, because these are four independent local calls and awaiting them in
    // sequence made the window's first paint the sum of their latencies rather than the
    // slowest one.
    const [info, notice] = await Promise.all([api.appInfo(), api.startupError()]);
    setStore({ info, settings: info.settings });
    if (notice) {
      setStore("startupNotice", notice);
      void api.logUiEvent("warn", `startup notice: ${notice}`);
    }
    await Promise.all([refreshProjects(), refreshRequests()]);
    setStore("ready", true);
    // Then Docker. Not awaited: the app is usable now, and a probe is three CLI calls, so
    // the status strip fills in when it answers instead of holding up the window.
    void refreshDockerStatus();
  } catch (error) {
    const text = describeError(error);
    setStore({ fatal: text, ready: true });
    // The window could not start. There is nowhere else for this to be read.
    void api.logUiEvent("error", `the window could not start: ${text}`);
  }
}

/**
 * Ask the backend about Docker, and put the answer where the status strip reads it.
 *
 * Separate from `bootstrap` on purpose: this is the slow part of starting up and none of
 * the first paint depends on it. A failure leaves `docker` as null, which the strip renders
 * as "checking" -- the honest state, rather than claiming the daemon is unreachable when
 * what failed was the question.
 */
let dockerRetry: number | null = null;

/**
 * Ask the backend about Docker, and put the answer where the status strip reads it.
 *
 * Separate from `bootstrap` on purpose: this is the slow part of starting up and none of the
 * first paint depends on it.
 *
 * A "no" is not an answer to keep. Docker Desktop is routinely still starting when the window
 * opens, and a probe taken then answers "the daemon is not reachable" -- which the app then
 * went on saying for the rest of the session, with Docker plainly running, because nothing
 * asked again. So while the answer is no, it keeps asking, until it is yes.
 */
export async function refreshDockerStatus() {
  try {
    const docker = await api.dockerStatus();
    setStore("info", "docker", docker);
    if (docker.available) {
      if (dockerRetry !== null) {
        window.clearTimeout(dockerRetry);
        dockerRetry = null;
      }
    } else {
      scheduleDockerRetry();
    }
  } catch {
    // The question failed rather than answering. Ask again: `info.docker` keeps whatever it
    // said last, which is the honest state of knowledge.
    scheduleDockerRetry();
  }
}

/** Look again in a moment, unless a look is already scheduled. */
function scheduleDockerRetry() {
  if (dockerRetry !== null) return;
  dockerRetry = window.setTimeout(() => {
    dockerRetry = null;
    void refreshDockerStatus();
  }, 10_000);
}

export async function refreshProjects() {
  const projects = await api.listProjects();
  setStore("projects", projects);
  // Keep a valid selection: fall back to the first project.
  if (!store.selectedId || !projects.some((p) => p.id === store.selectedId)) {
    setStore("selectedId", projects.length > 0 ? projects[0].id : null);
    if (projects.length > 0) await refreshProjectData(projects[0].id);
    else setStore({ grants: [], audit: [] });
  }
}

export async function selectProject(projectId: string) {
  setStore("selectedId", projectId);
  await refreshProjectData(projectId);
}

/** Drop a host from the "blocked" list once the operator has allowed it. */
export function clearBlockedEgress(host?: string) {
  if (!host) {
    setStore("blockedEgress", []);
    return;
  }
  setStore("blockedEgress", (list) => list.filter((entry) => entry.host !== host));
}

export async function refreshProjectData(projectId: string) {
  const [grants, audit] = await Promise.all([api.listGrants(projectId), api.auditLog(projectId, 200)]);
  setStore({ grants, audit });
}

export async function refreshSettings() {
  const [settings, info] = await Promise.all([api.getSettings(), api.appInfo()]);
  // `app_info` deliberately carries no Docker status: probing for it there put three Docker
  // CLI calls in front of the window's first paint. So keep the one already known -- replacing
  // it with null puts the strip back to "Checking Docker…" every time settings are reloaded,
  // which is what the operator saw as the app losing track of a daemon that was running.
  setStore({ settings, info: { ...info, docker: store.info?.docker ?? info.docker } });
}

/**
 * Ask the build that is running to stop.
 *
 * The build's own verdict arrives through the usual events -- the failure says it was stopped
 * rather than reporting a break -- so this only has to send the request and say what happened
 * to it. Both the header and the progress bar call this, so there is one implementation of the
 * decision and two places to make it from.
 */
export async function cancelBuild() {
  try {
    const stopped = await api.cancelBuild(store.buildImage);
    if (stopped.length > 0) {
      toast("info", "Stopping the build", "Its output so far is in the Activity tab.");
    } else {
      toast("warn", "Nothing to stop", "No build is running now.");
    }
  } catch (error) {
    toast("error", "Could not stop the build", describeError(error));
  }
}

/**
 * How long an operation on a session may stay "in flight" before the button is let go.
 *
 * A first Run builds an image, which takes minutes, so this is not a timeout on the work --
 * it is a floor on how long the operator can be locked out. The backend answers in every case
 * it knows about; this is for the case it does not answer at all, and fifteen minutes of a
 * disabled button with no explanation is what that looks like from the outside.
 */
const SESSION_BUSY_CEILING_MS = 15 * 60 * 1000;
let sessionBusyTimer: number | null = null;

/**
 * Run an operation on a project's session, with the button state kept where every button reads
 * it, and released whether the answer is a success, a failure, or nothing at all.
 *
 * The last case is the one that was missing: `finally` releases the button when a promise
 * settles, which is every outcome except the promise never settling -- and a start that never
 * answered left the button greyed out for the rest of the session, with the only way back being
 * to restart the app.
 */
export async function sessionOperation(
  projectId: string,
  run: () => Promise<unknown>,
): Promise<void> {
  if (store.sessionBusy !== null) {
    // Only this project's buttons are disabled, so a click on another project's Run would
    // otherwise do nothing at all, which reads as a broken button rather than as a queue.
    toast(
      "warn",
      "This project is already starting",
      "If it has been a while, it is most likely building the project image, which takes minutes the first time. That build writes into the terminal, and the sandbox starts on its own when it finishes.",
    );
    return;
  }
  setStore("sessionBusy", projectId);
  if (sessionBusyTimer !== null) window.clearTimeout(sessionBusyTimer);
  sessionBusyTimer = window.setTimeout(() => {
    sessionBusyTimer = null;
    if (store.sessionBusy !== projectId) return;
    setStore("sessionBusy", null);
    toast(
      "warn",
      "The sandbox is not answering",
      "Starting or stopping it has taken fifteen minutes without an answer, so the button is " +
        "available again. It may still be working: the Activity tab and the log have the details.",
    );
    void api.logUiEvent(
      "warn",
      `a session operation for ${projectId} did not answer within fifteen minutes`,
    );
  }, SESSION_BUSY_CEILING_MS);

  try {
    await run();
  } finally {
    releaseSession(projectId);
  }
}

/** Let go of the button, for a project whose operation has finished or has been answered. */
export function releaseSession(projectId: string) {
  if (store.sessionBusy !== projectId) return;
  if (sessionBusyTimer !== null) {
    window.clearTimeout(sessionBusyTimer);
    sessionBusyTimer = null;
  }
  setStore("sessionBusy", null);
}

export async function refreshRequests() {
  const requests = await api.listPendingRequests();
  setStore("requests", requests);
}

/* ------------------------------------------------------------------------- */
/* Event wiring                                                               */
/* ------------------------------------------------------------------------- */

/** Register every backend listener. Returns a disposer. */
export async function wireEvents(): Promise<() => void> {
  const unlisteners = await Promise.all([
    api.onTerminalOutput((payload) => {
      const listeners = terminalSinks.get(payload.projectId);
      if (!listeners || listeners.size === 0) return;
      const bytes = decodeBase64(payload.data);
      for (const sink of listeners) sink(bytes);
    }),

    api.onTerminalExit((payload) => {
      setStore("sessionErrors", payload.projectId, "");
      void refreshProjects();
      if (payload.code !== 0) {
        toast("warn", "The sandbox stopped", `DeepCode exited with code ${payload.code}.`);
      }
    }),

    api.onSessionStatus(() => {
      void refreshProjects();
    }),

    api.onBrokerRequest(async (request) => {
      setStore("requests", (list) =>
        list.some((entry) => entry.id === request.id) ? list : [...list, request],
      );
      void refreshProjects();
    }),

    api.onBrokerResolved((payload) => {
      setStore("requests", (list) => list.filter((entry) => entry.id !== payload.requestId));
      void refreshProjects();
      if (payload.decision === "allow") {
        toast("ok", "Access granted", "The sandbox is restarting with the new permission.");
      }
    }),

    api.onBrokerRejected((payload) => {
      setStore("rejected", (list) => [...list.slice(-24), payload]);
    }),

    api.onEgressBlocked((payload) => {
      setStore("blockedEgress", (list) =>
        list.some((entry) => entry.host === payload.host) ? list : [...list.slice(-24), payload],
      );
      void refreshSettings();
    }),

    api.onBuildLog((payload) => {
      setStore("buildLog", (list) => [...list.slice(-600), payload.line]);
      // A build can start without the UI asking: `start_session` builds the image on
      // the first Run for a tool selection. So the log arriving is what marks a build
      // as in progress, not the button that used to be the only way to start one.
      if (!store.building) {
        setStore("building", true);
        setStore("buildProgress", null);
        setStore("buildImage", null);
      }
    }),

    api.onBuildProgress((payload) => {
      setStore("building", true);
      setStore("buildImage", payload.image);
      setStore("buildProgress", { step: payload.step, total: payload.total });
    }),

    api.onBuildDone((payload) => {
      setStore("building", false);
      setStore("buildProgress", null);
      setStore("buildImage", null);
      if (payload.ok) {
        toast("ok", "Runtime image built");
        void refreshSettings();
      } else {
        toast("error", "Runtime image build failed", payload.detail);
      }
    }),

    // The host's settings file is watched by the backend; this is the window being told to
    // re-read what depends on it.
    /**
     * A tool-version check found something. The window says so, because the alternative is a
     * cache quietly emptying itself and the next build taking minutes longer for no visible
     * reason.
     */
    api.onToolUpdatesChecked((report) => {
      const first = report.notes[0] ?? "some cached tools have moved on";
      toast(
        "info",
        "Cached tools are out of date",
        `${first} The next build installs them again.`,
      );
    }),

    api.onHostConfigChanged(() => {
      setStore("configRevision", store.configRevision + 1);
      void api.logUiEvent("info", "the DeepCode settings file changed; re-read it");
    }),

    api.onStateChanged(() => {
      void refreshProjects();
      const current = store.selectedId;
      if (current) void refreshProjectData(current);
      // Docker appearing or disappearing is announced the same way, and the status shown to
      // the operator lives in `info`. This used to re-read it through `refreshSettings`, which
      // stopped carrying it when the probe moved off the startup path -- so the announcement
      // arrived and nothing was re-read. Ask for it directly.
      void refreshDockerStatus();
      void refreshSettings();
    }),
  ]);

  // Docker Desktop is usually started *because* the window said it was not running. Coming
  // back to the window is the moment to look again, rather than waiting up to ten seconds.
  const onFocus = () => {
    if (store.info?.docker?.available === false) void refreshDockerStatus();
  };
  window.addEventListener("focus", onFocus);

  // One quiet check for a newer Deepsand, a few seconds in so it does not compete with
  // the startup sweep and the Docker probe.
  //
  // Only a positive answer is worth interrupting for. A laptop that is offline, or a
  // GitHub that is rate-limiting, is not news -- and a toast saying "could not check for
  // updates" every launch is exactly the kind of noise that trains people to ignore
  // toasts. The Settings dialog shows that state when it is asked.
  window.setTimeout(() => {
    void api
      .checkForUpdates()
      .then((result) => {
        if (result.update) {
          toast(
            "info",
            `Deepsand ${result.update.version} is available`,
            "Open Settings to install it.",
          );
        }
      })
      .catch(() => undefined);
  }, 5000);

  return () => {
    window.removeEventListener("focus", onFocus);
    for (const unlisten of unlisteners) {
      try {
        unlisten();
      } catch {
        /* the window may already be gone */
      }
    }
  };
}

/* ------------------------------------------------------------------------- */
/* Terminal fan-out                                                           */
/* ------------------------------------------------------------------------- */

type TerminalSink = (bytes: Uint8Array) => void;

/**
 * Terminal output is delivered by event with no buffering, so a terminal that
 * is not currently mounted would lose it. The pane registers a sink while it is
 * on screen; the Rust side keeps the PTY alive either way.
 */
const terminalSinks = new Map<string, Set<TerminalSink>>();

export function attachTerminal(projectId: string, sink: TerminalSink): () => void {
  let set = terminalSinks.get(projectId);
  if (!set) {
    set = new Set();
    terminalSinks.set(projectId, set);
  }
  set.add(sink);
  return () => {
    const current = terminalSinks.get(projectId);
    if (!current) return;
    current.delete(sink);
    if (current.size === 0) terminalSinks.delete(projectId);
  };
}
