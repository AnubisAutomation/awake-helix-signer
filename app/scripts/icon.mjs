// Draw the app icon (a double helix on a dark rounded square) as a 1024 px PNG.
//
// The same drawing as the core's icon.rs (and the former Python signer), so the repository
// keeps no binary files: `npm run icons` writes src-tauri/app-icon.png with
// this script and lets `tauri icon` derive every platform's icon set from it
// (src-tauri/icons, including Android mipmaps and the iOS AppIcon set).
//
// Usage: node scripts/icon.mjs <out.png> [size]
import { writeFileSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { deflateSync } from "node:zlib";

const BACKGROUND = [11, 18, 32];
const STRANDS = [
  [45, 212, 191],
  [245, 158, 11],
];
const RUNG = [148, 163, 184];

const blend = (base, color, alpha) => base.map((b, i) => b + (color[i] - b) * alpha);

function pixels(size) {
  const scale = size / 256;
  const radius = 48 * scale;
  const amplitude = 54 * scale;
  const width = 15 * scale;
  const out = Buffer.alloc(size * (size * 4 + 1));
  let offset = 0;
  for (let y = 0; y < size; y++) {
    out[offset++] = 0; // PNG filter type 0
    const fy = y + 0.5;
    const phase = (fy / size) * 2.4 * Math.PI + 0.6;
    const centers = [size / 2 + amplitude * Math.sin(phase), size / 2 - amplitude * Math.sin(phase)];
    const depth = Math.cos(phase);
    for (let x = 0; x < size; x++) {
      const fx = x + 0.5;
      const dx = Math.max(radius - fx, 0, fx - (size - radius));
      const dy = Math.max(radius - fy, 0, fy - (size - radius));
      const coverage = dx || dy ? Math.max(0, Math.min(1, radius - Math.hypot(dx, dy) + 0.5)) : 1;
      let color = BACKGROUND;
      const rung = Math.abs(((fy / scale) % 32) - 16);
      const [low, high] = [...centers].sort((a, b) => a - b);
      if (rung > 13 && low < fx && fx < high) color = blend(color, RUNG, Math.min(1, (rung - 13) / 2) * 0.8);
      for (const index of depth > 0 ? [1, 0] : [0, 1]) {
        const alpha = Math.max(0, Math.min(1, width / 2 - Math.abs(fx - centers[index]) + 0.5));
        if (alpha) color = blend(color, STRANDS[index], alpha);
      }
      out[offset++] = Math.round(color[0]);
      out[offset++] = Math.round(color[1]);
      out[offset++] = Math.round(color[2]);
      out[offset++] = Math.round(255 * coverage);
    }
  }
  return out;
}

const CRC = new Int32Array(256).map((_, n) => {
  let c = n;
  for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
  return c;
});
function crc32(buffer) {
  let c = -1;
  for (const byte of buffer) c = CRC[(c ^ byte) & 0xff] ^ (c >>> 8);
  return (c ^ -1) >>> 0;
}
function chunk(kind, data) {
  const head = Buffer.alloc(4);
  head.writeUInt32BE(data.length);
  const body = Buffer.concat([Buffer.from(kind, "ascii"), data]);
  const tail = Buffer.alloc(4);
  tail.writeUInt32BE(crc32(body));
  return Buffer.concat([head, body, tail]);
}

export function png(size = 256) {
  const header = Buffer.alloc(13);
  header.writeUInt32BE(size, 0);
  header.writeUInt32BE(size, 4);
  header.set([8, 6, 0, 0, 0], 8);
  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    chunk("IHDR", header),
    chunk("IDAT", deflateSync(pixels(size), { level: 9 })),
    chunk("IEND", Buffer.alloc(0)),
  ]);
}

const [out, size] = process.argv.slice(2);
if (out) {
  mkdirSync(dirname(out), { recursive: true });
  writeFileSync(out, png(Number(size || 1024)));
  console.log(`wrote ${out}`);
}
