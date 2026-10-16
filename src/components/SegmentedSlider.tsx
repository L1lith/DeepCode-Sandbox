/**
 * A row of joined segments with one thumb that slides between them.
 *
 * One control for "exactly one of these", rather than a row of buttons and a selected class on
 * whichever is current: the thumb is the selection, so the control says "one of these" by
 * construction. `NetworkSlider` is this control with the four network modes wired in, and the
 * user-prompt mode is this control with three; a second copy of this markup is how the two would
 * come to look and behave differently.
 *
 * `role="radio"` and `aria-checked` on the segments, so a screen reader is told the same single
 * choice the eye is.
 */

import { createMemo, For } from "solid-js";

export interface Segment<T extends string> {
  value: T;
  label: string;
  /** Shown as the segment's title, for a label that needs a sentence to explain it. */
  title?: string;
}

export function SegmentedSlider<T extends string>(props: {
  options: Segment<T>[];
  value: T;
  onChange: (value: T) => void;
  ariaLabel: string;
  disabled?: boolean;
}) {
  /** Where the thumb sits. A value that is not in the list sits at the start rather than nowhere. */
  const index = createMemo(() => {
    const at = props.options.findIndex((option) => option.value === props.value);
    return at < 0 ? 0 : at;
  });

  return (
    <div
      class="mode-slider"
      role="radiogroup"
      aria-label={props.ariaLabel}
      style={{ "--segments": String(props.options.length) }}
    >
      {/* The only thing that moves, and the only thing that means "selected". */}
      <span
        class="mode-thumb"
        style={{ transform: `translateX(${index() * 100}%)` }}
        aria-hidden="true"
      />
      <For each={props.options}>
        {(option) => (
          <button
            type="button"
            role="radio"
            aria-checked={props.value === option.value}
            class="mode-segment"
            title={option.title}
            disabled={props.disabled}
            onClick={() => props.onChange(option.value)}
          >
            {option.label}
          </button>
        )}
      </For>
    </div>
  );
}
