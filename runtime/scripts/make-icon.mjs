#!/usr/bin/env node
/**
 * Generates the Deepsand app icon as a PNG, with no image-library dependency.
 *
 * The icon is a sandbox: a rounded container holding a smaller square, which is
 * the whole idea of the product in one glyph. Drawn procedurally so the shape
 * is described by code rather than committed as an opaque blob, and so the
 * repository stays free of binary assets nobody can regenerate.
 *
 * Usage:  node runtime/scripts/make-icon.mjs [output.png] [size]
 * Then:   npx tauri icon <output.png>   (produces src-tauri/icons/*)
 */

import { deflateSync } from "node:zlib";
import { writeFileSync, mkdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const SIZE = Number.parseInt(process.argv[3] ?? "1024", 10);
const HERE = path.dirname(fileURLToPath(import.meta.url));
const OUTPUT = process.argv[2] ?? path.join(HERE, "..", "..", "assets", "icon.png");

/* --- palette ------------------------------------------------------------- */
const BACKDROP = [0x14, 0x17, 0x22, 0xff];
const RIM = [0x4d, 0x6b, 0xfe, 0xff];
const INNER = [0x7c, 0x93, 0xff, 0xff];
const CORE = [0xe8, 0xec, 0xff, 0xff];
const GLOW = [0x4d, 0x6b, 0xfe, 0x55];

/* --- signed distance helpers -------------------------------------------- */
function roundedRectDistance(x, y, cx, cy, halfW, halfH, radius) {
  const dx = Math.abs(x - cx) - (halfW - radius);
  const dy = Math.abs(y - cy) - (halfH - radius);
  const ax = Math.max(dx, 0);
  const ay = Math.max(dy, 0);
  return Math.hypot(ax, ay) + Math.min(Math.max(dx, dy), 0) - radius;
}

function squareDistance(x, y, cx, cy, half, radius) {
  return roundedRectDistance(x, y, cx, cy, half, half, radius);
}

function smoothstep(edge0, edge1, value) {
  const t = Math.min(1, Math.max(0, (value - edge0) / (edge1 - edge0)));
  return t * t * (3 - 2 * t);
}

function blend(dst, src, alpha) {
  dst[0] = Math.round(dst[0] * (1 - alpha) + src[0] * alpha);
  dst[1] = Math.round(dst[1] * (1 - alpha) + src[1] * alpha);
  dst[2] = Math.round(dst[2] * (1 - alpha) + src[2] * alpha);
  dst[3] = Math.round(dst[3] * (1 - alpha) + src[3] * alpha);
}

/* --- render ------------------------------------------------------------- */
function render(size) {
  const pixels = Buffer.alloc(size * size * 4);
  const center = size / 2;
  const scale = size / 1024;

  // Rounded backdrop, corner radius ~22% (the squircle-ish shape used by
  // modern desktop launchers).
  const backdrop = { half: size * 0.5, radius: size * 0.22 };
  // Outer rim: a container wall.
  const rimHalf = 330 * scale;
  const rimThickness = 46 * scale;
  // Inner square: whatever is inside the sandbox.
  const innerHalf = 168 * scale;
  // Core: the contained process.
  const coreHalf = 74 * scale;

  for (let y = 0; y < size; y += 1) {
    for (let x = 0; x < size; x += 1) {
      const px = x + 0.5;
      const py = y + 0.5;
      const color = [0, 0, 0, 0];

      // Backdrop with anti-aliased edge.
      const backdropDistance = roundedRectDistance(px, py, center, center, backdrop.half, backdrop.half, backdrop.radius);
      const backdropAlpha = 1 - smoothstep(-1.2, 1.2, backdropDistance);
      if (backdropAlpha <= 0) {
        pixels.set([0, 0, 0, 0], (y * size + x) * 4);
        continue;
      }
      blend(color, BACKDROP, backdropAlpha);

      // A soft radial glow so the icon does not read as a flat slab at 16px.
      const radial = Math.hypot(px - center, py - center) / (size * 0.62);
      blend(color, GLOW, Math.max(0, 1 - radial) * 0.9 * backdropAlpha);

      // Container wall: outer rounded square minus a slightly smaller one.
      const rimOuter = squareDistance(px, py, center, center, rimHalf, rimHalf * 0.78);
      const wallAlpha = 1 - smoothstep(-1.4, 1.4, Math.abs(rimOuter) - rimThickness * 0.5);
      blend(color, RIM, wallAlpha * backdropAlpha);

      // The lip at the top, suggesting an opening the contents cannot leave.
      const lipY = center - rimHalf * 0.78;
      if (Math.abs(py - lipY) < rimThickness * 0.75 && Math.abs(px - center) < rimHalf) {
        const lipAlpha = 1 - smoothstep(rimThickness * 0.3, rimThickness * 0.75, Math.abs(py - lipY));
        blend(color, INNER, lipAlpha * 0.85 * backdropAlpha);
      }

      // The contained square.
      const inner = squareDistance(px, py, center, center + 6 * scale, innerHalf, innerHalf, 26 * scale);
      const innerAlpha = 1 - smoothstep(-1.4, 1.4, inner);
      blend(color, INNER, innerAlpha * 0.92 * backdropAlpha);

      // The core inside the contained square.
      const core = squareDistance(px, py, center, center + 6 * scale, coreHalf, coreHalf, 16 * scale);
      const coreAlpha = 1 - smoothstep(-1.4, 1.4, core);
      blend(color, CORE, coreAlpha * backdropAlpha);

      pixels.set(color, (y * size + x) * 4);
    }
  }
  return pixels;
}

/* --- PNG encoding ------------------------------------------------------- */
const CRC_TABLE = (() => {
  const table = new Int32Array(256);
  for (let n = 0; n < 256; n += 1) {
    let c = n;
    for (let k = 0; k < 8; k += 1) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    table[n] = c;
  }
  return table;
})();

function crc32(buffer) {
  let c = 0xffffffff;
  for (const byte of buffer) c = CRC_TABLE[(c ^ byte) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

function chunk(type, data) {
  const length = Buffer.alloc(4);
  length.writeUInt32BE(data.length, 0);
  const typeAndData = Buffer.concat([Buffer.from(type, "ascii"), data]);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(typeAndData), 0);
  return Buffer.concat([length, typeAndData, crc]);
}

function encodePng(pixels, size) {
  const signature = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);

  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(size, 0);
  ihdr.writeUInt32BE(size, 4);
  ihdr[8] = 8; // bit depth
  ihdr[9] = 6; // colour type: RGBA
  ihdr[10] = 0; // deflate
  ihdr[11] = 0; // adaptive filtering
  ihdr[12] = 0; // no interlace

  // Each scanline is prefixed with filter type 0 (None).
  const stride = size * 4;
  const raw = Buffer.alloc((stride + 1) * size);
  for (let y = 0; y < size; y += 1) {
    raw[y * (stride + 1)] = 0;
    pixels.copy(raw, y * (stride + 1) + 1, y * stride, (y + 1) * stride);
  }

  return Buffer.concat([
    signature,
    chunk("IHDR", ihdr),
    chunk("IDAT", deflateSync(raw, { level: 9 })),
    chunk("IEND", Buffer.alloc(0)),
  ]);
}

/* --- main --------------------------------------------------------------- */
const pixels = render(SIZE);
const png = encodePng(pixels, SIZE);
mkdirSync(path.dirname(OUTPUT), { recursive: true });
writeFileSync(OUTPUT, png);
console.log(`wrote ${OUTPUT} (${SIZE}x${SIZE}, ${(png.length / 1024).toFixed(1)} KiB)`);
