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
    if (notice) setStore("startupNotice", notice);
    await Promise.all([refreshProjects(), refreshRequests()]);
    setStore("ready", true);
    // Then Docker. Not awaited: the app is usable now, and a probe is three CLI calls, so
    // the status strip fills in when it answers instead of holding up the window.
    void refreshDockerStatus();
  } catch (error) {
    setStore({ fatal: describeError(error), ready: true });
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
export async function refreshDockerStatus() {
  try {
    const docker = await api.dockerStatus();
    setStore("info", "docker", docker);
  } catch {
    /* left as null: the strip keeps saying it is still checking */
  }
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
  setStore({ settings, info });
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

    api.onStateChanged(() => {
      void refreshProjects();
      const current = store.selectedId;
      if (current) void refreshProjectData(current);
      // Docker appearing or disappearing is announced the same way, and the status shown
      // to the operator lives in `info`, so it has to be re-read -- otherwise the app
      // keeps saying Docker is unavailable until it is restarted, which is the bug this
      // is here to fix.
      void refreshSettings();
    }),
  ]);

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
