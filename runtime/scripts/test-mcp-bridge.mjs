#!/usr/bin/env node
/**
 * Smoke test for the in-container MCP bridge.
 * ---------------------------------------------------------------------------
 * The bridge only talks to the host through three directories, so the host
 * broker can be simulated exactly: create a spool, spawn the bridge with the
 * spool pointed at it, speak MCP, and write response files the way the real
 * broker does.
 *
 * Run:  node runtime/scripts/test-mcp-bridge.mjs
 */

import { spawn } from "node:child_process";
import fsp from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const BRIDGE = path.join(HERE, "..", "bin", "deepsand-mcp-bridge.mjs");

let failures = 0;
let checks = 0;
const cleanups = [];
let currentSection = "";

function check(name, fn) {
  checks += 1;
  try {
    fn();
    console.log(`  \x1b[32mok\x1b[0m   ${name}`);
  } catch (err) {
    failures += 1;
    console.log(`  \x1b[31mFAIL\x1b[0m ${name}\n       ${String(err.message).split("\n")[0]}`);
    if (process.env.VERBOSE) console.log(err.stack);
  }
}

function section(title) {
  currentSection = title;
  console.log(`\n\x1b[1m${title}\x1b[0m`);
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/* ------------------------------------------------------------------------- */
/* A simulated host broker                                                    */
/* ------------------------------------------------------------------------- */

class HostBroker {
  constructor(spool) {
    this.spool = spool;
    this.requests = path.join(spool, "requests");
    this.responses = path.join(spool, "responses");
    this.handled = new Set();
  }

  async init() {
    for (const d of ["requests", "responses", "state"]) {
      await fsp.mkdir(path.join(this.spool, d), { recursive: true });
    }
    await this.writeState("sandbox.json", {
      network_mode: "internet",
      open_requests: [],
      notes: ["simulated by the smoke test"],
    });
    await this.writeState("grants.json", {
      grants: [{ host_path: "C:\\src\\shared-theme", container_path: "/grants/shared-theme", access: "read" }],
    });
  }

  async writeState(name, value) {
    await fsp.writeFile(path.join(this.spool, "state", name), JSON.stringify(value));
  }

  /** Every request file the bridge has published, oldest first. */
  async published() {
    try {
      const names = (await fsp.readdir(this.requests)).filter((n) => n.endsWith(".json"));
      const parsed = await Promise.all(
        names.map(async (n) => JSON.parse(await fsp.readFile(path.join(this.requests, n), "utf8"))),
      );
      return parsed.sort((a, b) => String(a.created_at).localeCompare(String(b.created_at)));
    } catch {
      return [];
    }
  }

  /** Wait for a request the harness has not seen yet, without answering it. */
  async awaitNew(kind, timeoutMs = 8000) {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      for (const req of await this.published()) {
        if (req.kind === kind && !this.handled.has(req.id)) {
          this.handled.add(req.id);
          return req;
        }
      }
      await sleep(25);
    }
    throw new Error(`timed out waiting for a '${kind}' request`);
  }

  /** Answer the next unseen request of `kind`, the way the real app would. */
  async answer(kind, payload) {
    const req = await this.awaitNew(kind);
    await this.respond(req.id, typeof payload === "function" ? payload(req) : payload);
    return req;
  }

  async respond(id, payload) {
    await fsp.writeFile(path.join(this.responses, `${id}.json`), JSON.stringify({ v: 1, id, ...payload }), "utf8");
  }
}

/* ------------------------------------------------------------------------- */
/* A client speaking MCP to the bridge over stdio                             */
/* ------------------------------------------------------------------------- */

class Bridge {
  constructor(spool) {
    this.spool = spool;
    this.nextId = 1;
    this.pending = new Map();
    this.stderr = [];
    this.stdoutLines = [];
  }

  async start() {
    this.child = spawn(process.execPath, [BRIDGE], {
      stdio: ["pipe", "pipe", "pipe"],
      env: {
        ...process.env,
        DEEPSAND_IPC_REQUESTS: path.join(this.spool, "requests"),
        DEEPSAND_IPC_RESPONSES: path.join(this.spool, "responses"),
        DEEPSAND_STATE_DIR: path.join(this.spool, "state"),
        DEEPSAND_WORKSPACE: "/workspace",
        DEEPSAND_PROJECT: "proj_test",
        DEEPSAND_WAIT_MS: "1500",
        DEEPSAND_POLL_MS: "50",
      },
    });
    cleanups.push(() => this.stop());

    this.child.stderr.on("data", (d) => this.stderr.push(d.toString("utf8")));

    let stdout = "";
    this.child.stdout.on("data", (chunk) => {
      stdout += chunk.toString("utf8");
      let nl;
      while ((nl = stdout.indexOf("\n")) !== -1) {
        const line = stdout.slice(0, nl).trim();
        stdout = stdout.slice(nl + 1);
        if (!line) continue;
        this.stdoutLines.push(line);
        const msg = JSON.parse(line); // throws if the bridge ever pollutes stdout
        if (msg.id === undefined || msg.id === null) continue;
        const entry = this.pending.get(msg.id);
        if (!entry) continue;
        this.pending.delete(msg.id);
        if (msg.error) entry.reject(new Error(`RPC error ${msg.error.code}: ${msg.error.message}`));
        else entry.resolve(msg.result);
      }
    });
  }

  send(method, params) {
    const id = this.nextId++;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        if (this.pending.delete(id)) reject(new Error(`${method} never answered`));
      }, 30_000);
      this.pending.set(id, {
        resolve: (v) => {
          clearTimeout(timer);
          resolve(v);
        },
        reject: (e) => {
          clearTimeout(timer);
          reject(e);
        },
      });
      this.child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", id, method, params })}\n`);
    });
  }

  notify(method, params) {
    this.child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", method, params })}\n`);
  }

  callTool(name, args) {
    return this.send("tools/call", { name, arguments: args });
  }

  stop() {
    try {
      this.child.stdin.end();
    } catch {
      /* already gone */
    }
  }
}

function textOf(result) {
  return (result?.content ?? []).map((c) => c.text ?? "").join("\n");
}

/* ------------------------------------------------------------------------- */

async function main() {
  const spool = await fsp.mkdtemp(path.join(os.tmpdir(), "deepsand-bridge-"));
  cleanups.push(() => fsp.rm(spool, { recursive: true, force: true }));

  const broker = new HostBroker(spool);
  await broker.init();

  const bridge = new Bridge(spool);
  await bridge.start();

  /* --------------------------------------------------------------------- */
  section("MCP handshake");

  const init = await bridge.send("initialize", {
    protocolVersion: "2025-03-26",
    capabilities: {},
    clientInfo: { name: "deepcode-cli", version: "0.1.0" },
  });
  check("initialize negotiates the protocol version DeepCode speaks", () => {
    assert.equal(init.protocolVersion, "2025-03-26");
    assert.equal(init.serverInfo.name, "deepsand");
    assert.ok(init.capabilities.tools, "must advertise a tools capability");
  });

  const legacy = await bridge.send("initialize", { protocolVersion: "1999-01-01" });
  check("an unknown protocol version falls back instead of failing the handshake", () =>
    assert.equal(legacy.protocolVersion, "2025-03-26"));

  bridge.notify("notifications/initialized");

  const tools = await bridge.send("tools/list", {});
  check("tools/list exposes exactly the documented tools", () => {
    assert.deepEqual(tools.tools.map((t) => t.name).sort(), [
      "deepsand_check_request",
      "deepsand_list_requests",
      "deepsand_request_directory_access",
      "deepsand_request_network_access",
      "deepsand_request_resource",
      "deepsand_request_secret",
      "deepsand_request_tool",
      "deepsand_sandbox_info",
    ]);
  });
  check("every tool has a substantial description and an object schema", () => {
    for (const t of tools.tools) {
      assert.ok(t.description.length > 80, `${t.name} description too short`);
      assert.equal(t.inputSchema.type, "object");
    }
  });

  assert.deepEqual((await bridge.send("prompts/list", {})).prompts, []);
  assert.deepEqual((await bridge.send("resources/list", {})).resources, []);
  assert.deepEqual((await bridge.send("resources/templates/list", {})).resourceTemplates, []);
  check("prompts/resources listings are answered so /mcp shows no errors", () => assert.ok(true));
  check("ping is answered", async () => assert.deepEqual(await bridge.send("ping", {}), {}));

  let unknownErrored = false;
  try {
    await bridge.send("totally/unknown", {});
  } catch (err) {
    unknownErrored = /Method not found/.test(err.message);
  }
  check("unknown methods return a JSON-RPC error, not a crash", () => assert.ok(unknownErrored));

  /* --------------------------------------------------------------------- */
  section("sandbox introspection");

  const info = textOf(await bridge.callTool("deepsand_sandbox_info", {}));
  check("reports the workspace as the pre-existing mount", () => assert.match(info, /\/workspace/));
  check("reports the egress policy, including what is blocked", () => {
    // The bridge's wording is not the contract; that the mode and the categories
    // it refuses are both spelled out is. The second assertion is what makes the
    // word "blocked" in the name mean something.
    assert.match(info, /public internet is reachable[\s\S]*refused by an address filter/);
    assert.match(info, /host machine[\s\S]*local\s+network[\s\S]*cloud metadata/);
  });
  check("lists the existing grant with its host path and access mode", () => {
    assert.match(info, /C:\\src\\shared-theme/);
    assert.match(info, /read-only/);
  });
  check("tells the model there is no alternate route to unlisted paths", () =>
    assert.match(info, /do not[\s\S]*go looking for one/));
  check("points the model at both request tools", () => {
    assert.match(info, /deepsand_request_directory_access/);
    assert.match(info, /deepsand_request_resource/);
  });

  /* --------------------------------------------------------------------- */
  section("the operator's standing instructions");

  // The other copy of this text is in the file Deepsand installs, and DeepCode ignores that file
  // whenever the project ships its own AGENTS.md -- which most repositories do. So the copy that
  // has to be there is this one: in the tool list, which no file in the project can shadow.
  const withoutPrompt = await bridge.send("tools/list", {});
  check("no instructions in the list when the operator has set none", () => {
    const tool = withoutPrompt.tools.find((t) => t.name === "deepsand_sandbox_info");
    assert.doesNotMatch(tool.description, /standing instructions/);
  });

  const INSTRUCTIONS = "Prefer small commits, and never touch the migrations folder.";
  const sandbox = JSON.parse(
    await fsp.readFile(path.join(broker.spool, "state", "sandbox.json"), "utf8"),
  );
  await broker.writeState("sandbox.json", { ...sandbox, user_prompt: INSTRUCTIONS });

  const withPrompt = await bridge.send("tools/list", {});
  check("the tool list carries the operator's instructions", () => {
    const tool = withPrompt.tools.find((t) => t.name === "deepsand_sandbox_info");
    assert.match(tool.description, /Prefer small commits/);
  });
  check("and no other tool grows the text", () => {
    for (const tool of withPrompt.tools.filter((t) => t.name !== "deepsand_sandbox_info")) {
      assert.doesNotMatch(tool.description, /Prefer small commits/);
    }
  });

  const infoWithPrompt = textOf(await bridge.callTool("deepsand_sandbox_info", {}));
  check("sandbox_info repeats them, where the model reads them in full", () =>
    assert.match(infoWithPrompt, /Standing instructions from the operator[\s\S]*Prefer small commits/));
  check("and says they do not widen what the sandbox can reach", () =>
    assert.match(infoWithPrompt, /do not widen what this sandbox can reach/));

  // Put the snapshot back, so the sections below see what the rest of the suite expects.
  await broker.writeState("sandbox.json", sandbox);

  /* --------------------------------------------------------------------- */
  section("directory access: the 'DeepCode is trying to access X directory' popup");

  const publishApproval = broker.answer("directory_access", (req) => ({
    decision: "allow",
    message: "shared it, be careful",
    restart_required: true,
    grant: { host_path: req.args.host_path, container_path: "/grants/brand", access: "write" },
  }));
  const approvedResult = await bridge.callTool("deepsand_request_directory_access", {
    host_path: "C:\\Users\\me\\Documents\\brand",
    access: "write",
    purpose: "Read the brand assets to generate the site palette.",
  });
  const dirReq = await publishApproval;
  const approved = textOf(approvedResult);

  check("the popup payload carries the exact host path, the access level and the purpose", () => {
    assert.equal(dirReq.args.host_path, "C:\\Users\\me\\Documents\\brand");
    assert.equal(dirReq.args.access, "write");
    assert.match(dirReq.args.purpose, /brand assets/);
  });
  check("the request is scoped to this project and workspace", () => {
    assert.equal(dirReq.project, "proj_test");
    assert.equal(dirReq.workspace, "/workspace");
    assert.equal(dirReq.v, 1);
  });
  check("the request carries no credential-shaped field", () => {
    // There used to be a `token` here that nothing validated: the bridge is a child of the
    // agent's own process, so anything it can read the agent can read. A field that looks
    // like authentication but is not is worse than no field, so its absence is asserted.
    for (const name of Object.keys(dirReq)) {
      assert.doesNotMatch(
        name,
        /token|secret|password|credential|api_?key/i,
        `the spool is unauthenticated; ${name} would imply otherwise`,
      );
    }
  });
  check("an approval tells the model where the resource now lives", () => {
    assert.match(approved, /APPROVED/);
    assert.match(approved, /\/grants\/brand/);
    assert.match(approved, /read-write/);
  });
  check("an approval warns that the container is about to be recreated", () =>
    assert.match(approved, /container to be recreated[\s\S]*restarts your[\s\S]*session/));
  check("the operator's note is relayed verbatim", () => assert.match(approved, /shared it, be careful/));

  /* --------------------------------------------------------------------- */
  section("directory access: denial");

  const publishDenial = broker.answer("directory_access", { decision: "deny", message: "absolutely not" });
  const deniedResult = await bridge.callTool("deepsand_request_directory_access", {
    host_path: "/home/me/.ssh",
    purpose: "Look for deploy keys.",
  });
  await publishDenial;
  const denied = textOf(deniedResult);

  check("a denial names the decision plainly", () => assert.match(denied, /DENIED/));
  check("a denial forbids retrying or routing around it", () => {
    assert.match(denied, /Do not retry/);
    // It used to claim "no workaround exists", which round 3 of the escape assessment
    // falsified on Docker Desktop. The instruction is what matters; the claim about the
    // environment is what had to go.
    assert.match(denied, /asking is the supported way/);
    assert.doesNotMatch(denied, /no workaround exists/);
  });
  check("a denial is a normal result, not an error, so the turn can continue", () =>
    assert.notEqual(deniedResult.isError, true));
  check("a denial is never announced as an approval", () => assert.doesNotMatch(denied, /APPROVED/));

  /* --------------------------------------------------------------------- */
  section("resource location: the 'DeepCode is requesting access to X' popup");

  const slow = bridge.callTool("deepsand_request_resource", {
    description: "the my-website repo with the shared theme",
    purpose: "Reuse its components.",
  });
  const locateReq = await broker.awaitNew("locate_resource");
  const pendingText = textOf(await slow);

  check("the popup carries the description, the kind and defaulted access", () => {
    assert.equal(locateReq.args.description, "the my-website repo with the shared theme");
    assert.equal(locateReq.args.kind, "directory");
    assert.equal(locateReq.args.access, "read", "access must default to read, the safe option");
  });
  check("a slow operator yields PENDING with a request id, not a lost request", () => {
    assert.match(pendingText, /PENDING/);
    assert.match(pendingText, new RegExp(locateReq.id));
  });
  check("the pending reply tells the model how to collect the answer", () =>
    assert.match(pendingText, /deepsand_check_request/));
  check("the pending reply forbids filing a duplicate request", () => assert.match(pendingText, /duplicate/));

  /* --------------------------------------------------------------------- */
  section("collecting a late answer");

  const stillPending = textOf(await bridge.callTool("deepsand_check_request", { request_id: locateReq.id }));
  check("check_request reports still-pending while the operator has not answered", () =>
    assert.match(stillPending, /Still PENDING/));

  // What a model needs after its own call timed out: it never saw the id, so the listing has to
  // name both the id and what it was for, or the id is not something it can act on.
  const listedWhileWaiting = textOf(await bridge.callTool("deepsand_list_requests", {}));
  check("list_requests names an outstanding request and what it was for", () => {
    assert.match(listedWhileWaiting, new RegExp(locateReq.id));
    assert.match(listedWhileWaiting, /waiting for the operator/);
    assert.match(listedWhileWaiting, /my-website/);
  });

  await broker.respond(locateReq.id, {
    decision: "allow",
    restart_required: true,
    grant: { host_path: "D:\\work\\my-website", container_path: "/grants/my-website", access: "read" },
  });
  const collected = textOf(await bridge.callTool("deepsand_check_request", { request_id: locateReq.id }));
  check("check_request returns the grant once the operator answers", () => {
    assert.match(collected, /APPROVED/);
    assert.match(collected, /\/grants\/my-website/);
    assert.match(collected, /read-only/);
  });
  check("the model is told it cannot write to a read-only grant", () =>
    assert.match(collected, /cannot modify it/));

  const listedAfterAnswer = textOf(await bridge.callTool("deepsand_list_requests", {}));
  check("list_requests shows a decision as collectable once the operator answers", () => {
    assert.match(listedAfterAnswer, new RegExp(locateReq.id));
    assert.match(listedAfterAnswer, /answered - read it with deepsand_check_request/);
  });

  const bogus = await bridge.callTool("deepsand_check_request", { request_id: "req_never_issued" });
  check("an id that was never issued is rejected", () => {
    assert.equal(bogus.isError, true);
    assert.match(textOf(bogus), /No request with id/);
  });

  /* --------------------------------------------------------------------- */
  section("input validation");

  const containerPath = await bridge.callTool("deepsand_request_directory_access", {
    host_path: "/workspace/../etc",
    purpose: "sneak-out-of-workspace",
  });
  check("a container path is refused rather than forwarded as a host path", () => {
    assert.equal(containerPath.isError, true);
    assert.match(textOf(containerPath), /is a container path/);
  });

  const grantsPath = await bridge.callTool("deepsand_request_directory_access", {
    host_path: "/grants/other-project",
    purpose: "sneak-sideways",
  });
  check("a /grants path is likewise refused", () => assert.equal(grantsPath.isError, true));

  const missingPurpose = await bridge.callTool("deepsand_request_resource", { description: "x" });
  check("a missing required field is rejected", () => assert.equal(missingPurpose.isError, true));

  const unknownTool = await bridge.callTool("deepsand_definitely_not_a_tool", {});
  // Awaited first, then asserted synchronously: `check` is not async, so passing it
  // an async function would record a pass without ever running the assertion.
  const noPatterns = await bridge.callTool("deepsand_request_network_access", {
    patterns: [],
    purpose: "why",
  });
  check("a network request must name at least one destination", () =>
    assert.equal(noPatterns.isError, true));

  const blanket = await bridge.callTool("deepsand_request_network_access", {
    patterns: ["*"],
    purpose: "because",
  });
  check("a blanket '*' is refused before a human ever sees it", () => {
    assert.equal(blanket.isError, true);
    // The refusal has to say what to do instead, not just no.
    assert.match(textOf(blanket), /Name the specific hosts/);
  });

  const networkNoPurpose = await bridge.callTool("deepsand_request_network_access", {
    patterns: ["registry.npmjs.org"],
  });
  check("a network request without a purpose is rejected", () =>
    assert.equal(networkNoPurpose.isError, true));

  const noTools = await bridge.callTool("deepsand_request_tool", { tools: [], purpose: "why" });
  check("a tool request must name at least one tool", () =>
    assert.equal(noTools.isError, true));

  const toolNoPurpose = await bridge.callTool("deepsand_request_tool", { tools: ["go"] });
  check("a tool request without a purpose is rejected", () =>
    assert.equal(toolNoPurpose.isError, true));

  // A well-formed request has to actually reach the operator, or the tools would be
  // useless: the point is that the popup appears.
  const networkPending = await bridge.callTool("deepsand_request_network_access", {
    patterns: ["registry.npmjs.org"],
    command: "npm install react",
    purpose: "installing dependencies",
  });
  check("a well-formed network request reaches the operator", () => {
    assert.notEqual(networkPending.isError, true);
    assert.match(textOf(networkPending), /PENDING|request_id/);
  });

  const toolPending = await bridge.callTool("deepsand_request_tool", {
    tools: ["python"],
    purpose: "running a build script",
  });
  check("a well-formed tool request reaches the operator", () => {
    assert.notEqual(toolPending.isError, true);
    assert.match(textOf(toolPending), /PENDING|request_id/);
  });

  check("an unknown tool name is rejected", () => assert.equal(unknownTool.isError, true));

  const all = await broker.published();
  const rejected = all.filter((r) => /sneak-/.test(String(r.args?.purpose ?? "")));
  check("rejected calls never reach the operator's screen", () => assert.equal(rejected.length, 0));

  /* --------------------------------------------------------------------- */
  section("robustness");

  bridge.child.stdin.write("this is not json\n");
  bridge.child.stdin.write('{"jsonrpc":"2.0"}\n');
  bridge.child.stdin.write('{"jsonrpc":"1.0","id":999,"method":"ping"}\n');
  bridge.child.stdin.write("\n");
  const afterGarbage = await bridge.send("ping", {});
  check("malformed input is ignored without killing the server", () => assert.deepEqual(afterGarbage, {}));

  const stderr = bridge.stderr.join("");
  check("diagnostics go to stderr, never to the RPC channel", () => {
    assert.match(stderr, /\[deepsand-mcp\] starting/);
    assert.doesNotMatch(stderr, /\{"jsonrpc"/);
  });
  check("every stdout line was valid JSON-RPC", () =>
    assert.ok(bridge.stdoutLines.every((l) => JSON.parse(l).jsonrpc === "2.0")));
  check("the bridge announced the spool paths and wait budget it is using", () => {
    assert.match(stderr, /requests=.*requests/);
    assert.match(stderr, /wait=1500ms/);
  });

  /* --------------------------------------------------------------------- */
  section("the operator can stop being asked");

  await broker.writeState("sandbox.json", {
    network_mode: "allowlisted",
    open_requests: [],
    notes: [],
    requests_enabled: false,
    requests_disabled_message: "REQUESTS-OFF-SENTINEL: do not ask again.",
  });

  const offInfo = await bridge.callTool("deepsand_sandbox_info", {});
  check("sandbox_info says requests are off, before the model composes one", () =>
    assert.match(textOf(offInfo), /requests\s*:\s*OFF/));

  // This branch matters as much as the flag: reading the allowlisted mode as
  // "unrestricted" would tell the model it can reach the open internet when it cannot.
  check("and an allowlisted sandbox is described as filtered, not as unrestricted", () => {
    assert.match(textOf(offInfo), /allowlisted hosts/);
    assert.doesNotMatch(textOf(offInfo), /unrestricted egress/);
  });

  const requestsBefore = (await broker.published()).length;
  const refused = await bridge.callTool("deepsand_request_directory_access", {
    host_path: "/home/me/anything",
    purpose: "testing the switch",
  });
  const requestsAfter = (await broker.published()).length;

  check("a request while requests are off returns the host's own words", () =>
    assert.match(textOf(refused), /REQUESTS-OFF-SENTINEL/));
  check("and is not an error, so the turn continues instead of retrying", () =>
    assert.notEqual(refused.isError, true));
  check("and nothing reaches the spool, so no dialog can appear", () =>
    assert.equal(requestsAfter, requestsBefore));

  // The flag is read per request, not cached at startup: turning it back on has to work
  // in a bridge that is already running.
  await broker.writeState("sandbox.json", {
    network_mode: "allowlisted",
    open_requests: [],
    notes: [],
    requests_enabled: true,
  });
  const afterSwitchOn = await bridge.callTool("deepsand_request_directory_access", {
    host_path: "/home/me/anything",
    purpose: "testing the switch",
  });
  const publishedAfterSwitchOn = await broker.published();
  check("turning it back on lets a request through again", () =>
    assert.match(textOf(afterSwitchOn), /PENDING/));
  check("and this time it did reach the spool", () =>
    assert.equal(publishedAfterSwitchOn.length, requestsBefore + 1));

  /* --------------------------------------------------------------------- */
  section("resilience");

  const orphan = new Bridge(path.join(spool, "nonexistent"));
  await orphan.start();
  const orphanResult = await orphan.callTool("deepsand_sandbox_info", {});
  check("a bridge whose spool is gone still answers introspection", () =>
    assert.match(textOf(orphanResult), /Deepsand sandbox/));

  const orphanRequest = await orphan.callTool("deepsand_request_directory_access", {
    host_path: "/home/me/x",
    purpose: "test",
  });
  check("and explains that the broker is unreachable instead of hanging", () => {
    assert.equal(orphanRequest.isError, true);
    assert.match(textOf(orphanRequest), /permission broker/);
  });

  console.log(`\n${checks - failures}/${checks} checks passed  [${currentSection}]`);
}

main()
  .catch((err) => {
    console.error(`\nharness error: ${err.stack ?? err}`);
    failures += 1;
  })
  .finally(async () => {
    for (const fn of cleanups.reverse()) {
      try {
        await fn();
      } catch {
        /* best effort */
      }
    }
    if (failures > 0) process.exitCode = 1;
  });
