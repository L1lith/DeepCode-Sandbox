#!/usr/bin/env node
/**
 * Build the desktop app for local use.
 *
 * `npm run app:build` is the shipping build, and it is slow by design: the release profile
 * is `lto = true` with `codegen-units = 1`, so the link is a whole-program one and takes
 * minutes. Swapping the *linker* does not help -- measured on this repository, a release
 * relink after touching one file takes 219 s with the MSVC `link.exe` and 212 s with
 * `rust-lld`, because with LTO the time is LLVM optimizing across every crate *before* any
 * linker runs. The lever is LTO itself.
 *
 * So this turns LTO off and raises the codegen unit count, which produces a binary that is
 * slightly larger and slightly slower and builds far faster. `npm run app:build` stays the
 * one that ships.
 *
 * It is a script rather than a one-line npm script because setting environment variables
 * portably from package.json otherwise needs a helper dependency, and one small file is a
 * better trade than a new dependency in a project that deliberately has few.
 *
 *   npm run app:build:fast     release profile, LTO off, NSIS installer, unsigned
 *   npm run app:build:debug    debug profile, faster still, unoptimized
 *
 * Anything after these flags is passed through to `tauri build`.
 */
import { spawnSync } from "node:child_process";
import path from "node:path";

const argv = process.argv.slice(2);
const debug = argv.includes("--debug");
const passthrough = argv.filter((arg) => arg !== "--debug");

const env = { ...process.env };
if (!debug) {
  env.CARGO_PROFILE_RELEASE_LTO = "false";
  env.CARGO_PROFILE_RELEASE_CODEGEN_UNITS = "16";
}

// `--bundles nsis` on purpose: `bundle.targets` is "all" so that each platform in the
// release matrix builds its own artifacts, and on Windows that means both the MSI and the
// NSIS installer. A local build wants one of them, and the MSI needs WiX.
const args = [
  "build",
  "--bundles",
  "nsis",
  // Signing is for releases. Doing it here would need the key in the environment, which is
  // a needless reason for a local build to fail.
  "--no-sign",
  ...(debug ? ["--debug"] : []),
  ...passthrough,
];

const tauri = path.join(
  "node_modules",
  ".bin",
  process.platform === "win32" ? "tauri.cmd" : "tauri",
);

console.log(
  `build-app: tauri ${args.join(" ")}${
    debug ? "   (debug profile)" : "   (release profile, LTO off)"
  }`,
);

const result = spawnSync(tauri, args, {
  stdio: "inherit",
  env,
  shell: process.platform === "win32",
});

process.exit(result.status ?? 1);
