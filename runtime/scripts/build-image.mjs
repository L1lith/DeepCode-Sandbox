#!/usr/bin/env node
/**
 * Builds the Deepsand runtime image.
 *
 * Equivalent to the Activity tab's "Build image" button, for people who would
 * rather stay in a terminal. Reads the image tag out of Deepsand's own state so
 * the two never disagree.
 *
 * Usage:
 *   node runtime/scripts/build-image.mjs [tag]
 *
 * Environment:
 *   DEEPSAND_DATA_DIR   override where Deepsand keeps its state
 *   DEEPSAND_BUILD_ARGS extra `docker build` arguments, space separated
 *                       (e.g. --build-arg INSTALL_BUILD_TOOLS=1)
 */

import { spawn } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const RUNTIME_DIR = path.resolve(HERE, "..");
const DEFAULT_TAG = "deepsand/runtime:0.1.0";

function dataDir() {
  if (process.env.DEEPSAND_DATA_DIR) return process.env.DEEPSAND_DATA_DIR;
  const home = os.homedir();
  if (process.platform === "win32") {
    const local = process.env.LOCALAPPDATA ?? path.join(home, "AppData", "Local");
    return path.join(local, "Deepsand");
  }
  if (process.platform === "darwin") {
    return path.join(home, "Library", "Application Support", "Deepsand");
  }
  return path.join(home, ".local", "share", "Deepsand");
}

/** Prefer the tag the app is actually configured to use. */
function configuredTag() {
  const statePath = path.join(dataDir(), "state.json");
  if (!existsSync(statePath)) return null;
  try {
    const parsed = JSON.parse(readFileSync(statePath, "utf8"));
    const image = parsed?.settings?.image;
    return typeof image === "string" && image.trim() ? image.trim() : null;
  } catch {
    return null;
  }
}

const tag = process.argv[2] ?? configuredTag() ?? DEFAULT_TAG;
const extraArgs = (process.env.DEEPSAND_BUILD_ARGS ?? "").split(/\s+/).filter(Boolean);

if (!existsSync(path.join(RUNTIME_DIR, "Dockerfile"))) {
  console.error(`error: no Dockerfile at ${path.join(RUNTIME_DIR, "Dockerfile")}`);
  process.exit(1);
}

console.log(`building ${tag}`);
console.log(`  context : ${RUNTIME_DIR}`);
if (extraArgs.length) console.log(`  extra   : ${extraArgs.join(" ")}`);
console.log("");

const child = spawn(
  "docker",
  ["build", "--tag", tag, "--file", path.join(RUNTIME_DIR, "Dockerfile"), ...extraArgs, RUNTIME_DIR],
  { stdio: "inherit" },
);

child.on("error", (error) => {
  console.error(`error: could not run docker: ${error.message}`);
  console.error("Is Docker Desktop installed and running?");
  process.exit(1);
});

child.on("close", (code) => {
  if (code === 0) {
    console.log("");
    console.log(`done. ${tag} is ready.`);
    console.log("Start a project from Deepsand, or: deepsandctl run <project>");
  } else {
    console.error("");
    console.error(`docker build failed with exit code ${code}`);
  }
  process.exit(code ?? 1);
});
