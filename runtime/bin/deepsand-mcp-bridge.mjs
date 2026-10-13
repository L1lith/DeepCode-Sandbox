#!/usr/bin/env node
/**
 * Deepsand MCP bridge — runs *inside* the sandbox container.
 * ---------------------------------------------------------------------------
 * This process is how the contained DeepCode instance asks the human operator
 * for something it cannot reach. It is deliberately powerless:
 *
 *   * It speaks MCP (newline-delimited JSON-RPC 2.0) on stdin/stdout, which is
 *     the only channel DeepCode can spawn it through.
 *   * It can WRITE request files into  <requests>/  (rw bind mount).
 *   * It can READ response files from    <responses>/ (ro bind mount).
 *   * It can READ sandbox state from     <state>/     (ro bind mount).
 *
 * The single security-relevant invariant is the mount mode of <responses> and
 * <state>: they are mounted READ-ONLY, so nothing inside the sandbox can forge
 * an approval, rewrite its own grant list, or fabricate state. The sandbox can
 * only ever *ask*. Every decision is made by the Deepsand desktop app running
 * on the host, outside the sandbox.
 *
 * DeepCode caps MCP tools/call at 60 s (MCP_CALL_TOOL_TIMEOUT_MS in
 * packages/core/src/mcp/mcp-manager.ts), so a request that is still awaiting a
 * human answer returns "pending" plus a request id, and the model polls with
 * deepsand_check_request.
 */

import { createInterface } from "node:readline";
import fs from "node:fs";
import fsp from "node:fs/promises";
import path from "node:path";
import crypto from "node:crypto";
import os from "node:os";

const PROTOCOL_VERSION = "2025-03-26";
const SUPPORTED_PROTOCOL_VERSIONS = new Set(["2025-03-26", "2024-11-05"]);
const SERVER_INFO = { name: "deepsand", version: "0.1.0" };

const REQUESTS_DIR = process.env.DEEPSAND_IPC_REQUESTS || "/deepsand/ipc/requests";
const RESPONSES_DIR = process.env.DEEPSAND_IPC_RESPONSES || "/deepsand/ipc/responses";
const STATE_DIR = process.env.DEEPSAND_STATE_DIR || "/deepsand/state";
const WORKSPACE = process.env.DEEPSAND_WORKSPACE || "/workspace";
// No session token. There used to be one, echoed into every request file, and nothing ever
// checked it: this bridge is spawned by the agent's own DeepCode process as uid 1000, so
// any value it can read the agent can read. Carrying it made the spool look authenticated
// when it is not. See docs/SECURITY.md, "The request spool is not authenticated".
const PROJECT_ID = process.env.DEEPSAND_PROJECT || "";
/** Stay comfortably under DeepCode's 60 s tools/call budget. */
const WAIT_MS = clampInt(process.env.DEEPSAND_WAIT_MS, 500, 55_000, 45_000);
const POLL_MS = clampInt(process.env.DEEPSAND_POLL_MS, 50, 5_000, 200);

function clampInt(raw, min, max, fallback) {
  const n = Number.parseInt(String(raw ?? ""), 10);
  if (!Number.isFinite(n)) return fallback;
  return Math.min(max, Math.max(min, n));
}

function log(...args) {
  // stdout is the RPC channel; diagnostics must never touch it.
  process.stderr.write(`[deepsand-mcp] ${args.join(" ")}\n`);
}

/* ------------------------------------------------------------------------- */
/* Tools                                                                      */
/* ------------------------------------------------------------------------- */

const TOOLS = [
  {
    name: "deepsand_sandbox_info",
    description:
      "Describe this sandbox: the workspace path, the network policy, and every host resource that has currently been " +
      "shared into it. Call this before assuming a path does not exist, and call it again after the sandbox restarts " +
      "to discover newly shared mount points. The sandbox cannot see anything that is not listed here, and there is no " +
      "way to reach outside it by any other means.",
    inputSchema: { type: "object", properties: {}, additionalProperties: false },
  },
  {
    name: "deepsand_request_directory_access",
    description:
      "Ask the human operator to share a host directory with this sandbox, when you already know or can reasonably guess " +
      "its path on the host machine. Use this when the user refers to a specific folder such as their documents, another " +
      "repository, a config directory, or an asset library. The operator sees a dialog naming the exact path and chooses " +
      "whether to grant read-only or read-write access. If granted, the directory appears under /grants and the sandbox " +
      "is restarted with it mounted; the new path is returned to you.",
    inputSchema: {
      type: "object",
      properties: {
        host_path: {
          type: "string",
          description:
            "The path on the host machine, as the user would write it (for example 'C:\\\\Users\\\\me\\\\Documents' or " +
            "'/home/me/notes'). Absolute host paths only; do not pass container paths such as /workspace.",
        },
        access: {
          type: "string",
          enum: ["read", "write"],
          description:
            "'read' for inspection only (safest, prefer this), 'write' only if you must create or modify files there.",
        },
        purpose: {
          type: "string",
          description: "One short sentence explaining what you need it for, shown to the operator verbatim.",
        },
      },
      required: ["host_path", "purpose"],
      additionalProperties: false,
    },
  },
  {
    name: "deepsand_request_resource",
    description:
      "Ask the human operator to locate and share something you need but cannot see, when you know WHAT you need but " +
      "not WHERE it lives on the host machine. Use this when the user mentions a resource that is not inside the " +
      "workspace - for example a sibling project, a dataset, a credentials file, an SDK install, or 'my other repo'. " +
      "The operator is shown your description and a folder picker so they can find it for you. You will be told the " +
      "resulting mount path once the sandbox restarts.",
    inputSchema: {
      type: "object",
      properties: {
        description: {
          type: "string",
          description:
            "What you are looking for, in the user's terms (for example 'the my-website repo with the shared theme'). " +
            "This is the text the operator sees in the title of the prompt.",
        },
        kind: {
          type: "string",
          enum: ["directory", "file"],
          description: "What the operator should point at. Defaults to 'directory'.",
        },
        access: {
          type: "string",
          enum: ["read", "write"],
          description: "'read' to inspect only, 'write' to modify. Defaults to 'read'.",
        },
        purpose: {
          type: "string",
          description: "One short sentence explaining why you need it.",
        },
      },
      required: ["description", "purpose"],
      additionalProperties: false,
    },
  },
  {
    name: "deepsand_request_network_access",
    description:
      "Ask the operator to let this sandbox reach a destination the network policy is blocking. Use this when a " +
      "command failed because of the allowlist: a package install, a git clone, a fetch from an API. Prefer the " +
      "narrowest pattern that will work, and a hostname over a wildcard. If the operator denies it you may make ONE " +
      "further request with a narrower pattern; do not repeat the same one.",
    inputSchema: {
      type: "object",
      properties: {
        patterns: {
          type: "array",
          items: { type: "string" },
          description:
            "One or more destinations. 'registry.npmjs.org' matches that host exactly on any port, and " +
            "'registry.npmjs.org:8443' matches only that port. '*.example.com' matches its subdomains but " +
            "not the apex. 'host/path' limits a host to paths under that prefix (plain HTTP only - a " +
            "CONNECT tunnel carries no path). An IP literal such as '192.168.1.50:5432' is reached " +
            "directly, which is what a database or any non-HTTP client needs. '!host' denies. Never '*'. " +
            "A hostname that resolves into local or private address space is refused even when allowed, " +
            "and the refusal names the address to ask for instead - ask for the address, not the name.",
        },
        command: {
          type: "string",
          description:
            "The command that was blocked, copied verbatim. The operator needs it to judge whether the request is " +
            "reasonable, and it is the single most useful thing you can include.",
        },
        purpose: {
          type: "string",
          description: "One short sentence explaining what you need it for, shown to the operator verbatim.",
        },
      },
      required: ["patterns", "purpose"],
      additionalProperties: false,
    },
  },
  {
    name: "deepsand_request_tool",
    description:
      "Ask the operator to install a tool into this sandbox's container image. Only a fixed catalogue exists; call " +
      "deepsand_sandbox_info first to see which ids there are and which are already installed. A tool is baked into " +
      "the image, so it is NOT usable until the operator rebuilds and restarts the sandbox. Do not try to install it " +
      "yourself in the meantime - it would not persist, and for a package manager it would not even be the same thing.",
    inputSchema: {
      type: "object",
      properties: {
        tools: {
          type: "array",
          items: { type: "string" },
          description:
            "Tool ids from the catalogue, for example ['go'], or ['python', 'jq']. Request several at once if you " +
            "know you need them together, rather than one at a time.",
        },
        purpose: {
          type: "string",
          description: "One short sentence explaining what you need them for.",
        },
      },
      required: ["tools", "purpose"],
      additionalProperties: false,
    },
  },
  {
    name: "deepsand_check_request",
    description:
      "Check the result of a permission request that previously returned 'pending'. Returns the operator's decision and, " +
      "if granted, the container path where the resource can now be found.",
    inputSchema: {
      type: "object",
      properties: {
        request_id: { type: "string", description: "The request_id returned by the original call." },
      },
      required: ["request_id"],
      additionalProperties: false,
    },
  },
];

/* ------------------------------------------------------------------------- */
/* IPC with the host broker                                                   */
/* ------------------------------------------------------------------------- */

/**
 * Fail loudly and immediately if the broker spool is not usable.
 *
 * Checking the *reply* channel up front matters: without it a broken mount
 * would make every request sit in the queue for the full wait budget and then
 * report "pending", which looks to the model like a slow human rather than a
 * broken sandbox. Better to say so on the first call.
 */
async function ensureSpool() {
  try {
    await fsp.mkdir(REQUESTS_DIR, { recursive: true });
  } catch (err) {
    throw new Error(
      `the sandbox cannot reach the Deepsand permission broker (${REQUESTS_DIR} is not writable: ${err.message}). ` +
        `Report this to the operator; do not try to work around it.`,
    );
  }
  try {
    const stat = await fsp.stat(RESPONSES_DIR);
    if (!stat.isDirectory()) throw new Error("not a directory");
  } catch (err) {
    throw new Error(
      `the sandbox cannot see the Deepsand permission broker's reply channel (${RESPONSES_DIR}: ${err.message}), so ` +
        `no request could ever be answered. Report this to the operator; do not retry.`,
    );
  }
}

/** True while the request file is still sitting in the spool unanswered. */
async function requestStillOpen(id) {
  try {
    await fsp.access(path.join(REQUESTS_DIR, `${id}.json`));
    return true;
  } catch {
    return false;
  }
}

async function writeRequestFile(request) {
  await ensureSpool();
  const finalPath = path.join(REQUESTS_DIR, `${request.id}.json`);
  const tmpPath = path.join(REQUESTS_DIR, `.${request.id}.json.part`);
  await fsp.writeFile(tmpPath, JSON.stringify(request), { encoding: "utf8", mode: 0o600 });
  await fsp.rename(tmpPath, finalPath); // atomic publish; the host watcher sees a complete file
}

async function readResponseFile(id) {
  const p = path.join(RESPONSES_DIR, `${id}.json`);
  try {
    const raw = await fsp.readFile(p, "utf8");
    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed !== "object") return null;
    if (parsed.id !== id) return null;
    return parsed;
  } catch {
    return null;
  }
}

async function readState() {
  const out = {};
  for (const [key, file] of [
    ["sandbox", "sandbox.json"],
    ["grants", "grants.json"],
  ]) {
    try {
      out[key] = JSON.parse(await fsp.readFile(path.join(STATE_DIR, file), "utf8"));
    } catch {
      out[key] = null;
    }
  }
  return out;
}

function newRequestId() {
  return `req_${Date.now().toString(36)}_${crypto.randomBytes(6).toString("hex")}`;
}

/**
 * Ids this bridge process has issued. Used by deepsand_check_request so a
 * genuinely outstanding request is never mistaken for a bogus id, even if the
 * host has not refreshed its state snapshot yet.
 */
const issuedRequestIds = new Set();

/**
 * Submit a request and wait up to WAIT_MS for a human answer.
 * Returns { status: "answered", response } or { status: "pending", id }.
 *
 * The file is not authenticated and cannot be: `pid` is a hint for the operator's benefit,
 * not a credential, and the host treats the whole file as hostile input. The control is
 * that a human reads the request before anything is granted.
 */
async function submitAndWait(kind, args) {
  const id = newRequestId();
  issuedRequestIds.add(id);
  const request = {
    v: 1,
    id,
    kind,
    project: PROJECT_ID,
    workspace: WORKSPACE,
    args,
    created_at: new Date().toISOString(),
    pid: process.pid,
  };
  await writeRequestFile(request);

  const deadline = Date.now() + WAIT_MS;
  while (Date.now() < deadline) {
    const response = await readResponseFile(id);
    if (response) return { status: "answered", response };
    await new Promise((r) => setTimeout(r, POLL_MS));
  }
  return { status: "pending", id };
}

/* ------------------------------------------------------------------------- */
/* Rendering                                                                  */
/* ------------------------------------------------------------------------- */

function textResult(text, isError = false) {
  return { content: [{ type: "text", text }], isError };
}

function describeGrant(g) {
  const mode = g.access === "write" ? "read-write" : "read-only";
  return `  - ${g.host_path ?? "(unknown host path)"}\n      mounted at ${g.container_path} (${mode})`;
}

async function sandboxInfoText() {
  const state = await readState();
  const lines = [
    "# Deepsand sandbox",
    "",
    `workspace   : ${WORKSPACE}   <- the only pre-existing mount`,
    `container   : ${os.hostname()} (Linux, uid ${typeof process.getuid === "function" ? process.getuid() : "n/a"})`,
  ];

  if (state.sandbox) {
    const s = state.sandbox;
    const tools = s.tools ?? [];
    lines.push(
      `tools       : ${tools.length > 0 ? tools.join(", ") : "none (the image was built without any)"}`,
    );
    lines.push(`network     : ${s.network_mode ?? "unknown"}`);
    if (s.network_mode === "restricted") {
      lines.push(`              the model API and the hosts below are reachable over IP; everything else is`);
      lines.push(`              refused, including the local network. The filter is an address filter:`);
      lines.push(`              it governs IPv4 and IPv6 destinations, and nothing more.`);
      const hosts = s.egress_allowlist ?? [];
      lines.push(`              allowlisted hosts: ${hosts.length ? hosts.join(", ") : "(none yet)"}`);
    } else if (s.network_mode === "internet") {
      lines.push(`              the public internet is reachable over IP; the host machine, the local`);
      lines.push(`              network and cloud metadata addresses are refused by an address filter.`);
    } else if (s.network_mode === "none") {
      lines.push(`              only the model API is reachable. Package installs, git clones and web`);
      lines.push(`              requests will fail, as will anything an enabled tool would reach.`);
    } else {
      lines.push(`              unrestricted egress, including the host machine.`);
    }
    if (Array.isArray(s.notes) && s.notes.length) {
      for (const n of s.notes) lines.push(`note        : ${n}`);
    }
  }

  lines.push("", "Shared host resources:");
  const grants = Array.isArray(state.grants?.grants) ? state.grants.grants : [];
  if (grants.length === 0) {
    lines.push("  (none - the operator has not shared anything beyond the workspace)");
  } else {
    for (const g of grants) lines.push(describeGrant(g));
  }

  lines.push(
    "",
    "Anything not listed above does not exist as far as this sandbox is concerned. Filesystem isolation is",
    "enforced by the container runtime, not by policy, so there is no alternative path to those paths - do not",
    "go looking for one.",
    "",
    "Need something more? Four tools, one per kind of need:",
    "",
    "  deepsand_request_directory_access  - you can name the host path",
    "  deepsand_request_resource          - you know what you need but not where it lives",
    "  deepsand_request_network_access    - a destination the network policy is blocking",
    "  deepsand_request_tool              - a program that is not installed",
    "",
    "Approved directory access is applied by recreating this container, which restarts your session.",
    "Approved network access takes effect at once. An approved tool needs its image rebuilt first, so it",
    "will not be usable until then.",
  );
  return lines.join("\n");
}

function renderDecision(kind, response) {
  const decision = response.decision;
  const message = response.message ? `\n\nOperator note: ${response.message}` : "";

  if (decision === "deny") {
    // An instruction, not a claim about the environment. The old wording said the resource
    // "is not reachable from inside this sandbox and no workaround exists", which round 3 of
    // the escape assessment falsified on Docker Desktop: a `grpcfuse` share resolves
    // backslash path components, so a guessed host path can still be stat()ed for its size
    // and mtime even though it cannot be opened. Telling the model something untrue about
    // its own sandbox is how it learns to distrust the true statements too, so this now
    // says what the operator decided rather than asserting a property of the sandbox.
    return textResult(
      `DENIED. The operator refused this request. Do not retry it and do not look for another way to reach the ` +
        `resource: asking is the supported way to reach it, and the answer is no. Continue with what you ` +
        `have, or ask the operator how they would like to proceed.${message}`,
    );
  }

  if (decision === "allow") {
    const grant = response.grant ?? {};
    const parts = [`APPROVED.`, ""];
    if (grant.container_path) {
      parts.push(`The resource is now available at: ${grant.container_path}`);
      if (grant.access === "write") parts.push(`Access level: read-write`);
      else parts.push(`Access level: read-only (you cannot modify it)`);
      if (grant.host_path) parts.push(`Host path (for display in replies only): ${grant.host_path}`);
    } else {
      parts.push(`The operator marked this request as resolved.`);
    }
    if (response.restart_required) {
      parts.push(
        "",
        "IMPORTANT: applying this change requires the sandbox container to be recreated, which restarts your",
        "session. Deepsand does this automatically and resumes this conversation. If the path above is not yet",
        "visible, call deepsand_sandbox_info again after the restart.",
      );
    } else {
      parts.push("", "This resource was already available; no restart was needed.");
    }
    return textResult(parts.join("\n") + message);
  }

  return textResult(`Unrecognised decision '${decision}' for a ${kind} request.`, true);
}

/**
 * Accept either a single string or an array of them, trimmed and without blanks.
 *
 * A model that sends one value instead of a list should still produce a usable
 * request rather than an empty one that looks like the operator's fault.
 */
function normaliseStrings(value) {
  const list = Array.isArray(value) ? value : [value];
  return list.map((item) => String(item ?? "").trim()).filter(Boolean);
}

function renderPending(kind, id, verb) {
  return textResult(
    [
      `PENDING. The operator has not answered this ${kind} request yet (it has been surfaced in the Deepsand window).`,
      "",
      `request_id: ${id}`,
      "",
      `Call deepsand_check_request with that request_id to collect ${verb}. Do not submit a duplicate request for the`,
      `same resource - ask the operator to look at the Deepsand window instead.`,
    ].join("\n"),
  );
}

/* ------------------------------------------------------------------------- */
/* Tool dispatch                                                              */
/* ------------------------------------------------------------------------- */

async function callTool(name, args) {
  switch (name) {
    case "deepsand_sandbox_info":
      return textResult(await sandboxInfoText());

    case "deepsand_request_directory_access": {
      const hostPath = String(args?.host_path ?? "").trim();
      const purpose = String(args?.purpose ?? "").trim();
      if (!hostPath) return textResult("host_path is required.", true);
      if (!purpose) return textResult("purpose is required.", true);
      if (hostPath.startsWith("/workspace") || hostPath.startsWith("/grants") || hostPath.startsWith("/deepsand")) {
        return textResult(
          `'${hostPath}' is a container path, not a host path. Use deepsand_sandbox_info to see what is already ` +
            `mounted, and pass the path as the user would write it on their own machine.`,
          true,
        );
      }
      const access = args?.access === "write" ? "write" : "read";
      const outcome = await submitAndWait("directory_access", { host_path: hostPath, access, purpose });
      if (outcome.status === "pending") return renderPending("directory access", outcome.id, "the decision");
      return renderDecision("directory", outcome.response);
    }

    case "deepsand_request_resource": {
      const description = String(args?.description ?? "").trim();
      const purpose = String(args?.purpose ?? "").trim();
      if (!description) return textResult("description is required.", true);
      if (!purpose) return textResult("purpose is required.", true);
      const kindArg = args?.kind === "file" ? "file" : "directory";
      const access = args?.access === "write" ? "write" : "read";
      const outcome = await submitAndWait("locate_resource", { description, kind: kindArg, access, purpose });
      if (outcome.status === "pending") return renderPending("resource", outcome.id, "the result");
      return renderDecision("resource", outcome.response);
    }

    case "deepsand_request_network_access": {
      const purpose = String(args?.purpose ?? "").trim();
      if (!purpose) return textResult("purpose is required.", true);
      const patterns = normaliseStrings(args?.patterns);
      if (patterns.length === 0) {
        return textResult("patterns must name at least one destination.", true);
      }
      // Refused here as well as on the host: the request never reaches a human, so
      // nobody is put in the position of having to refuse it.
      if (patterns.some((pattern) => pattern === "*")) {
        return textResult(
          "Refusing to ask for '*'. Name the specific hosts you need - a blanket allow is not something to put in " +
            "front of a person to approve.",
          true,
        );
      }
      const command = String(args?.command ?? "").trim();
      const outcome = await submitAndWait("network_access", { patterns, command, purpose });
      if (outcome.status === "pending") return renderPending("network access", outcome.id, "the decision");
      return renderDecision("network", outcome.response);
    }

    case "deepsand_request_tool": {
      const purpose = String(args?.purpose ?? "").trim();
      if (!purpose) return textResult("purpose is required.", true);
      const tools = normaliseStrings(args?.tools);
      if (tools.length === 0) return textResult("tools must name at least one tool id.", true);
      const outcome = await submitAndWait("tool_install", { tools, purpose });
      if (outcome.status === "pending") return renderPending("tool", outcome.id, "the decision");
      return renderDecision("tool", outcome.response);
    }

    case "deepsand_check_request": {
      const id = String(args?.request_id ?? "").trim();
      if (!id) return textResult("request_id is required.", true);
      const response = await readResponseFile(id);
      if (!response) {
        // A request is outstanding if we issued it and either its request file
        // is still in the spool or the operator simply has not answered yet.
        // Never tell the model its own live request does not exist.
        if (issuedRequestIds.has(id) || (await requestStillOpen(id))) {
          return textResult(
            `Still PENDING. The operator has not answered yet. Ask them to check the Deepsand window, then call ` +
              `deepsand_check_request again with ${id}.`,
            false,
          );
        }
        return textResult(
          `No request with id ${id} exists. It may have been withdrawn, or the id is wrong. ` +
            `Call deepsand_sandbox_info to review the current state, then submit a fresh request if it is still needed.`,
          true,
        );
      }
      return renderDecision("request", response);
    }

    default:
      return textResult(`Unknown tool '${name}'.`, true);
  }
}

/* ------------------------------------------------------------------------- */
/* JSON-RPC / MCP server                                                      */
/* ------------------------------------------------------------------------- */

function writeMessage(message) {
  process.stdout.write(`${JSON.stringify(message)}\n`);
}

function sendResult(id, result) {
  writeMessage({ jsonrpc: "2.0", id, result });
}

function sendError(id, code, message, data) {
  writeMessage({ jsonrpc: "2.0", id, error: { code, message, ...(data === undefined ? {} : { data }) } });
}

async function handleRequest(msg) {
  const { id, method } = msg;
  const params = msg.params ?? {};

  switch (method) {
    case "initialize": {
      const requested = params.protocolVersion;
      const negotiated = SUPPORTED_PROTOCOL_VERSIONS.has(requested) ? requested : PROTOCOL_VERSION;
      sendResult(id, {
        protocolVersion: negotiated,
        capabilities: { tools: { listChanged: false } },
        serverInfo: SERVER_INFO,
      });
      return;
    }

    case "ping":
      sendResult(id, {});
      return;

    case "tools/list":
      sendResult(id, { tools: TOOLS });
      return;

    case "tools/call": {
      const name = typeof params.name === "string" ? params.name : "";
      const args = params.arguments && typeof params.arguments === "object" ? params.arguments : {};
      try {
        sendResult(id, await callTool(name, args));
      } catch (err) {
        log(`tools/call ${name} failed: ${err.stack || err.message}`);
        sendResult(
          id,
          textResult(
            `Deepsand bridge error while handling '${name}': ${err.message}. Tell the operator about this; do not ` +
              `retry in a loop.`,
            true,
          ),
        );
      }
      return;
    }

    // We advertise no prompts/resources, but answer politely so a client that
    // probes for them does not see a hard error in its logs.
    case "prompts/list":
      sendResult(id, { prompts: [] });
      return;
    case "resources/list":
      sendResult(id, { resources: [] });
      return;
    case "resources/templates/list":
      sendResult(id, { resourceTemplates: [] });
      return;
    case "logging/setLevel":
      sendResult(id, {});
      return;

    default:
      sendError(id, -32601, `Method not found: ${method}`);
  }
}

function handleNotification(msg) {
  switch (msg.method) {
    case "notifications/initialized":
    case "notifications/cancelled":
      return;
    default:
      log(`ignoring notification ${msg.method}`);
  }
}

function main() {
  log(
    `starting: project=${PROJECT_ID || "?"} workspace=${WORKSPACE} requests=${REQUESTS_DIR} ` +
      `responses=${RESPONSES_DIR} wait=${WAIT_MS}ms`,
  );
  if (!fs.existsSync(RESPONSES_DIR)) {
    log(`WARNING: ${RESPONSES_DIR} does not exist; permission requests will always time out as pending`);
  }

  const rl = createInterface({ input: process.stdin, crlfDelay: Infinity });
  let chain = Promise.resolve();

  rl.on("line", (line) => {
    const trimmed = line.trim();
    if (!trimmed) return;
    let msg;
    try {
      msg = JSON.parse(trimmed);
    } catch {
      log(`dropping unparseable line (${trimmed.length} bytes)`);
      return;
    }
    if (!msg || typeof msg !== "object" || msg.jsonrpc !== "2.0") return;
    if (msg.id === undefined || msg.id === null) {
      handleNotification(msg);
      return;
    }
    // Serialise handling so two concurrent tool calls cannot interleave their
    // writes into the request spool.
    chain = chain.then(() => handleRequest(msg)).catch((err) => {
      log(`request handling failed: ${err.stack || err.message}`);
      sendError(msg.id, -32603, `Internal error: ${err.message}`);
    });
  });

  rl.on("close", () => {
    log("stdin closed; exiting");
    process.exit(0);
  });
}

main();
