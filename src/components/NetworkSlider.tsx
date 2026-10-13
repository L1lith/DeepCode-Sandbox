/**
 * The four network modes as one control, with a thumb that slides between them.
 *
 * A row of joined segments rather than four separate buttons: they are one choice, and the old row
 * of buttons read as four independent actions. The selected state is a single element that moves,
 * so the control says "one of these" by construction rather than by lighting one button up and
 * hoping it reads that way.
 *
 * The order is the argument: `none` is the most restricted mode and `full` the least, so the thumb
 * runs from one end of that range to the other.
 *
 * `role="radio"` and `aria-checked` on the segments, so a screen reader is told the same single
 * choice the eye is.
 */

import { createMemo, For } from "solid-js";
import { networkLabel, policyMode, type NetworkPolicy } from "../lib/types";

/** Most restricted first: the order is the argument this control makes. */
const MODES: NetworkPolicy["mode"][] = ["none", "allowlisted", "internet", "full"];

export function NetworkSlider(props: {
  value: NetworkPolicy["mode"];
  onChange: (mode: NetworkPolicy["mode"]) => void;
  disabled?: boolean;
}) {
  /** Where the thumb sits. An unknown mode sits at the start rather than nowhere. */
  const index = createMemo(() => {
    const at = MODES.indexOf(policyMode({ mode: props.value, allow: [] } as NetworkPolicy));
    return at < 0 ? 0 : at;
  });

  return (
    <div class="mode-slider" role="radiogroup" aria-label="Network access">
      {/* The only thing that moves, and the only thing that means "selected". */}
      <span
        class="mode-thumb"
        style={{ transform: `translateX(${index() * 100}%)` }}
        aria-hidden="true"
      />
      <For each={MODES}>
        {(mode) => (
          <button
            type="button"
            role="radio"
            aria-checked={props.value === mode}
            class="mode-segment"
            disabled={props.disabled}
            onClick={() => props.onChange(mode)}
          >
            {networkLabel({ mode, allow: [] } as NetworkPolicy)}
          </button>
        )}
      </For>
    </div>
  );
}
