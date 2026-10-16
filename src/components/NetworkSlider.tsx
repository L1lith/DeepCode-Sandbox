/**
 * The four network modes as one control, with a thumb that slides between them.
 *
 * The sliding and the markup are `SegmentedSlider`'s; this file is only the network part of it:
 * which modes exist, and what they are called. The order is the argument: `none` is the most
 * restricted mode and `full` the least, so the thumb runs from one end of that range to the other.
 */

import { createMemo } from "solid-js";
import { networkLabel, policyMode, type NetworkPolicy } from "../lib/types";
import { SegmentedSlider } from "./SegmentedSlider";

/** Most restricted first: the order is the argument this control makes. */
const MODES: NetworkPolicy["mode"][] = ["none", "allowlisted", "internet", "full"];

/** The mode a policy is really in: `restricted` is the stored old name for `allowlisted`. */
function asMode(value: NetworkPolicy["mode"]): NetworkPolicy["mode"] {
  return policyMode({ mode: value, allow: [] } as NetworkPolicy);
}

export function NetworkSlider(props: {
  value: NetworkPolicy["mode"];
  onChange: (mode: NetworkPolicy["mode"]) => void;
  disabled?: boolean;
}) {
  /** Where the thumb sits. An unknown mode sits at the start rather than nowhere. */
  const current = createMemo(() => asMode(props.value));

  return (
    <SegmentedSlider
      ariaLabel="Network access"
      value={current()}
      disabled={props.disabled}
      onChange={props.onChange}
      options={MODES.map((mode) => ({
        value: mode,
        label: networkLabel({ mode, allow: [] } as NetworkPolicy),
      }))}
    />
  );
}
