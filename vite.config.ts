import { defineConfig } from "vite";
import solid from "vite-plugin-solid";

// Tauri serves the built bundle from `dist/` and talks to the Rust side over
// its own IPC, so the dev server only needs a fixed port and must not watch the
// Rust trees (which would otherwise trigger rebuild storms).
export default defineConfig({
  plugins: [solid()],
  clearScreen: false,
  server: {
    port: 1420,
    strictPort: true,
    host: "127.0.0.1",
    watch: {
      ignored: ["**/src-tauri/**", "**/crates/**", "**/reference/**", "**/runtime/**"],
    },
  },
  build: {
    target: "esnext",
    outDir: "dist",
    emptyOutDir: true,
    sourcemap: false,
  },
  envPrefix: ["VITE_", "TAURI_"],
});
