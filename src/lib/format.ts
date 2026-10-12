/** Small formatting helpers shared by the panels. */

const encoder = new TextEncoder();

/** Decode the base64 the Rust side uses for PTY bytes. */
export function decodeBase64(value: string): Uint8Array {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
}

export function encodeUtf8(value: string): Uint8Array {
  return encoder.encode(value);
}

/** Show the last path segment, which is what a person recognises. */
export function baseName(path: string): string {
  const normalised = path.replace(/[\\/]+$/, "");
  const parts = normalised.split(/[\\/]/);
  return parts[parts.length - 1] || normalised;
}

export function relativeTime(ms: number, now = Date.now()): string {
  const delta = Math.max(0, now - ms);
  const seconds = Math.floor(delta / 1000);
  if (seconds < 5) return "just now";
  if (seconds < 60) return `${seconds}s ago`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

export function formatTimestamp(ms: number): string {
  if (!ms) return "unknown";
  return new Date(ms).toLocaleString();
}

/** Turn "DeepCode is trying to access X" into a short badge label. */
export function shortPath(path: string, max = 46): string {
  if (path.length <= max) return path;
  const tail = path.slice(-(max - 1));
  return `…${tail}`;
}

export function clamp(value: number, min: number, max: number): number {
  return Math.min(max, Math.max(min, value));
}
