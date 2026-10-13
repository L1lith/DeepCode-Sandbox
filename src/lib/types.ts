/**
 * Types mirroring the Rust payloads in `src-tauri/src/state.rs`.
 *
 * Serde serialises those structs as camelCase, and the enums in
 * `deepsand-core::model` keep their own shape (`Access` is "read"/"write",
 * `NetworkPolicy` is an internally-tagged object). Keeping this file in sync is
 * the only contract between the two halves of the app.
 */

export type Access = "read" | "write";

export type NetworkPolicy =
  | { mode: "none" }
  | { mode: "internet" }
  // Stored as `allowlisted`. A state file written before the rename says
  // `restricted`; the backend still reads that and rewrites it on the next save.
  | { mode: "allowlisted"; allow: string[] }
  | { mode: "full" };

export type DeepCodeMode = "allow_all" | "strict";

export type CredentialSource = "inherit_host" | "project";

export interface Credentials {
  source: CredentialSource;
  model?: string | null;
  base_url?: string | null;
  api_key?: string | null;
  thinking_enabled?: boolean | null;
  reasoning_effort?: string | null;
  extra_env?: Record<string, string>;
}

/**
 * One project's network allowlist, as the backend resolves it.
 *
 * `project` is the half the operator edits for this project; `global` is the
 * app-wide list it inherits, shown read-only so the full picture is visible
 * without a second screen. `effective` is the union actually enforced.
 */
/**
 * What a remote client may do. Each is independent, and the default is
 * "watch and drive, but do not widen anything".
 */
export interface RemoteCapabilities {
  control: boolean;
  /** Answer permission requests, change grants and allowlists. */
  grantPermissions: boolean;
  manageProjects: boolean;
  /** Network mode, hardening, credentials, and the remote config itself. */
  changeSecurity: boolean;
}

export type RemoteScope = { kind: "app" } | { kind: "project"; projectId: string };

export interface RemoteServerConfig {
  id: string;
  label: string;
  scope: RemoteScope;
  bind: string;
  port: number;
  tls: "off" | "selfSigned";
  capabilities: RemoteCapabilities;
  token: string;
}

export interface RemoteAccessSettings {
  /** The feature toggle. While false the UI shows none of this. */
  enabled: boolean;
  persistAcrossRestarts: boolean;
  lockoutAfterFailures: number;
  servers: RemoteServerConfig[];
}

export interface RemoteServerView {
  id: string;
  label: string;
  scopeKind: "app" | "project";
  projectId: string | null;
  bind: string;
  port: number;
  tls: "off" | "selfSigned";
  capabilities: RemoteCapabilities;
  token: string;
  redactedToken: string;
  displayUrl: string;
  loopbackOnly: boolean;
  running: boolean;
  boundAddr: string | null;
}

export interface RemoteAccessView {
  enabled: boolean;
  persistAcrossRestarts: boolean;
  lockoutAfterFailures: number;
  servers: RemoteServerView[];
  uiDir: string | null;
}

export interface SecretView {
  name: string;
  /** A placeholder. The real value never leaves the backend. */
  masked: string;
  /** Worth knowing only for spotting a truncated paste. */
  length: number;
}

export interface SecretListView {
  projectId: string;
  secrets: SecretView[];
  /** False when the encryption key could not be opened, with the reason why. */
  available: boolean;
  unavailableReason: string | null;
  /** True when a sandbox is running and would need a restart to see a change. */
  restartNeeded: boolean;
  /** Names that cannot be used, so the form can refuse them up front. */
  reserved: string[];
}

export interface ToolView {
  id: string;
  label: string;
  description: string;
  category: string;
  provider: string;
  defaultOn: boolean;
  enabled: boolean;
  /** False when this tool cannot be installed into the runtime image at all. */
  available: boolean;
  /** Why not, so a greyed-out row explains itself. */
  unavailableReason: string | null;
  /** Hosts the tool opens in the network filter while it is on. */
  hosts: string[];
  /**
   * The base image the tool needs.
   *
   * A tool is never unavailable because of the operator's operating system -- the
   * container is always Linux. It is unavailable because the image is not the one it
   * needs, which is what this names.
   */
  requires: string;
}

export interface ToolCatalogView {
  projectId: string;
  tools: ToolView[];
  /** Hosts the enabled tools contribute to this project's allowlist. */
  effectiveHosts: string[];
  /** The image tag this selection builds to. */
  image: string;
  runningImage: string | null;
}

export interface EffortOption {
  value: string;
  label: string;
  /** What the state means, shown as the slider's tooltip. */
  description: string;
}

export interface EffortView {
  projectId: string;
  /** "none" | "low" | "high" | "max" | "default" */
  value: string;
  options: EffortOption[];
  controlling: boolean;
  /** True only when a running sandbox did not receive the change. */
  restartNeeded: boolean;
  /** True when this project defers to the operator's own settings.json. */
  deferring: boolean;
  /** Whether a running sandbox received the change as well as it being saved. */
  appliedLive: boolean;
}

export interface AllowlistView {
  projectId: string;
  /** The project's network mode. None of this applies unless the mode is allowlisted. */
  mode: string;
  /** False when the mode means the list is never consulted. */
  allowlisted: boolean;
  project: string[];
  global: string[];
  effective: string[];
  /** Entries that will not parse, and so are doing nothing. */
  problems: string[];
  /** Entries that parse but widen access a great deal. */
  risky: string[];
}

export interface ResourceLimits {
  memory_mb: number;
  cpus: number;
  pids_limit: number;
  tmpfs_mb: number;
  stop_timeout_s: number;
}

export interface SecuritySettings {
  seccomp: "default" | "hardened";
  read_only_rootfs: boolean;
  netfilter_required: boolean;
  no_new_privileges: boolean;
  apparmor: boolean;
  tmpfs_noexec: boolean;
}

export interface AppSettings {
  image: string;
  default_network: NetworkPolicy;
  default_limits: ResourceLimits;
  security: SecuritySettings;
  egress_allowlist: string[];
  auto_restart_on_grant: boolean;
  notify_on_request: boolean;
  default_base_url: string;
  default_model: string;
  data_dir?: string | null;
}

export interface ProjectView {
  id: string;
  name: string;
  slug: string;
  rootDir: string;
  createdAtMs: number;
  network: NetworkPolicy;
  limits: ResourceLimits;
  credentials: Credentials;
  deepcodeMode: DeepCodeMode;
  allowedRoots: string[];
  notes: string;
  /** Whether the sandbox may ask for permissions at all. On unless turned off. */
  requestsEnabled: boolean;
  containerName: string;
  running: boolean;
  workspaceExists: boolean;
  grantCount: number;
  pendingRequests: number;
}

/** A newer version than the one this build reports. */
export interface UpdateInfo {
  version: string;
  notes: string;
  /** RFC 3339, when the release announced a date. */
  date: string | null;
}

/**
 * The answer to "is there a newer Deepsand?".
 *
 * Three-valued on purpose: `update: null` with `error: null` means up to date, and a set
 * `error` means the question could not be asked. Reporting a dead network as "up to
 * date" would be a claim the operator has no way to check.
 */
export interface UpdateCheck {
  currentVersion: string;
  update: UpdateInfo | null;
  error: string | null;
}

/** Download progress, as the Rust side reports it. */
export type UpdateProgress =
  | { phase: "downloading"; downloaded: number; total: number | null }
  | { phase: "installing" };

export interface DockerStatus {
  available: boolean;
  client_version: string;
  server_version: string;
  operating_system: string;
  desktop: boolean;
  image_present: boolean;
  detail: string;
}

export interface AppInfo {
  version: string;
  dataDir: string;
  docker: DockerStatus;
  hostConfig: Record<string, string>;
  settings: AppSettings;
}

export interface GrantView {
  id: string;
  projectId: string;
  hostPath: string;
  containerPath: string;
  slug: string;
  access: Access;
  label: string;
  purpose: string;
  source: string;
  createdAtMs: number;
  exists: boolean;
}

export interface PlanPreview {
  text: string;
  warnings: string[];
  mountCount: number;
  networkMode: string;
  image: string;
  containerName: string;
  credentialProvenance: string;
  apiKeyPresent: boolean;
}

export interface PathCheck {
  allowed: boolean;
  resolved: string | null;
  reason: string | null;
}

export interface SessionStatus {
  projectId: string;
  running: boolean;
  commandLine: string | null;
  containerName: string;
  networkMode: string;
  warnings: string[];
}

export interface PermissionRequestView {
  id: string;
  projectId: string;
  projectName: string;
  /**
   * Which of the four request tools the agent used.
   *
   * "network_access" and "tool_install" reuse the same dialog; the backend writes a
   * `title` per kind, and `description` carries the destinations or tool names for
   * those two.
   */
  kind: "directory_access" | "locate_resource" | "network_access" | "tool_install";
  title: string;
  description: string;
  purpose: string | null;
  requestedAccess: "read" | "write";
  requestedKind: "directory" | "file";
  hasClaimedPath: boolean;
  claimedPath: string | null;
  claimedPathRejection: string | null;
  receivedAt: string;
  surfacedAtMs: number;
  provenance: string;
}

export interface RejectedRequestView {
  projectId: string;
  file: string;
  reason: string;
}

export interface BlockedEgressView {
  host: string;
  port: number;
  atMs: number;
  reason: string;
}

export interface DecisionPayload {
  requestId: string;
  decision: "allow" | "deny";
  message: string;
  hostPath?: string | null;
  access?: "read" | "write" | null;
  restart?: boolean | null;
}

export const DEFAULT_LIMITS: ResourceLimits = {
  memory_mb: 4096,
  cpus: 2,
  pids_limit: 512,
  tmpfs_mb: 2048,
  stop_timeout_s: 10,
};

/** Human label for a network policy, used in badges and pickers. */
export function networkLabel(policy: NetworkPolicy): string {
  switch (policy.mode) {
    case "none":
      return "no network";
    case "internet":
      return "internet only";
    case "allowlisted":
      return "allowlisted";
    case "full":
      return "full egress";
  }
}

export function networkDescription(policy: NetworkPolicy): string {
  switch (policy.mode) {
    case "none":
      return "Nothing is reachable except the model API itself. Package installs, git clones and web requests will all fail, as will anything the enabled tools would otherwise reach — the sandbox has no way out other than the address its model is served from.";
    case "internet":
      return "Public internet is reachable. The host machine, your local network, link-local addresses and cloud metadata endpoints are blocked by the container's own kernel rules.";
    case "allowlisted":
      return "Only what you list is reachable. A hostname you list goes through Deepsand's proxy; an address you list is reached directly, so a database or any non-HTTP client works. An entry with no port covers every port, and a port you list is also published on this machine's loopback so you can reach a server the sandbox runs there. A hostname that resolves into local or private address space is still refused — list the address itself to reach it on purpose.";
    case "full":
      return "No egress restriction at all, including this machine's own network services. Filesystem isolation is unaffected, but prefer a narrower mode.";
  }
}

export function accessLabel(access: Access): string {
  return access === "write" ? "read-write" : "read-only";
}
