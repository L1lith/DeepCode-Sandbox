/**
 * The four network modes as one control.
 *
 * A row of joined segments rather than four separate buttons: they are one choice, and the old row
 * of buttons read as four independent actions, which is why it looked wrong. The order is the
 * point of a slider too -- `none` is the most restricted and `full` the least, so the control now
 * runs from one end of that range to the other instead of listing the modes in an arbitrary order.
 *
 * `aria-checked` and `role="radio"` rather than styled buttons, so the keyboard and a screen
 * reader see the same single choice everybody else does.
 */

import { For } from "solid-js";
import { networkLabel, type NetworkPolicy } from "../lib/types";

/** Most restricted first: the order is the argument this control makes. */
const MODES: NetworkPolicy["mode"][] = ["none", "allowlisted", "internet", "full"];

export function NetworkSlider(props: {
  value: NetworkPolicy["mode"];
  onChange: (mode: NetworkPolicy["mode"]) => void;
  disabled?: boolean;
}) {
  return (
    <div class="mode-slider" role="radiogroup" aria-label="Network access">
      <For each={MODES}>
        {(mode) => (
          <button
            type="button"
            role="radio"
            aria-checked={props.value === mode}
            class="mode-segment"
            classList={{ "mode-segment-on": props.value === mode }}
            disabled={props.disabled}
            onClick={() => props.onChange(mode)}
          >
            {networkLabel({ mode, allow: [] })}
          </button>
        )}
      </For>
    </div>
  );
}
