/**
 * A progress bar for a runtime image build.
 *
 * Shown while the tools are being installed, which is the slowest thing Deepsand does
 * and until now the least visible: a first Run builds the image before the sandbox can
 * start, and the only sign was a log on another tab.
 *
 * The percentage comes from the build's own step numbering, so it is real. When the
 * build reports no steps the bar is indeterminate rather than sitting at 0%, because a
 * bar that never moves looks like a hang.
 */

import { createMemo, createSignal, Show } from "solid-js";
import { cancelBuild, store } from "../store";

export function BuildProgress() {
  /** Only to stop a second click landing while the first is being answered. */
  const [stopping, setStopping] = createSignal(false);
  const percent = createMemo(() => {
    const progress = store.buildProgress;
    if (!progress || progress.total === 0) return null;
    return Math.min(100, Math.round((progress.step / progress.total) * 100));
  });

  /** The last log line that says something, as the current step. */
  const latest = createMemo(() => {
    for (let index = store.buildLog.length - 1; index >= 0; index -= 1) {
      const line = (store.buildLog[index] ?? "").trim();
      if (line) return line.length > 160 ? `${line.slice(0, 157)}…` : line;
    }
    return "Starting the build…";
  });

  const image = () => store.buildImage ?? "the runtime image";

  return (
    <Show when={store.building || store.buildWait !== null}>
      <div class="build-bar" role="status" aria-live="polite">
        <div class="build-bar-head">
          <span class="build-bar-title">
            {store.building ? "Installing tools" : "Waiting for the image build"}
          </span>
          <Show
            when={percent() !== null}
            fallback={<span class="build-bar-pct">working…</span>}
          >
            <span class="build-bar-pct">{percent()}%</span>
          </Show>
        </div>

        {/* `aria-valuenow` is omitted when indeterminate, rather than set to 0, so a
            screen reader can tell "unknown" from "not started". */}
        <div
          class="build-bar-track"
          classList={{ "build-bar-indeterminate": percent() === null }}
          role="progressbar"
          aria-label={`Building ${image()}`}
          aria-valuemin={0}
          aria-valuemax={100}
          aria-valuenow={percent() ?? undefined}
        >
          <div class="build-bar-fill" style={{ width: percent() === null ? "100%" : `${percent()}%` }} />
        </div>

        <div class="build-bar-foot">
          <Show when={store.buildProgress}>
            {(progress) => (
              <span class="build-bar-step">
                Step {progress().step} of {progress().total}
              </span>
            )}
          </Show>
          <span class="build-bar-latest mono">{latest()}</span>
          {/* A build can take minutes and can stall, and the only other way out of a stalled
              one is to close the app. */}
          <button
            class="btn btn-sm build-bar-stop"
            disabled={stopping()}
            onClick={() => {
              setStopping(true);
              void cancelBuild().finally(() => setStopping(false));
            }}
          >
            Stop build
          </button>
        </div>
      </div>
    </Show>
  );
}
