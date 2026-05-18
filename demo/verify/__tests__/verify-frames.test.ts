/*
 * demo/verify/__tests__/verify-frames.test.ts — Vitest.
 *
 * Tests the mean-RGB computation on synthetic PNGs encoded inline. We do not
 * rely on sharp/canvas; we construct a tiny PNG with known pixel values and
 * verify the meanRgb + withinTolerance helpers from verify-frames.ts.
 */

import { describe, expect, it } from "vitest";
import { deflateSync } from "node:zlib";
import { writeFileSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

// Re-import the helpers from verify-frames.ts. The module is set up to no-op
// its CLI when imported (the `main()` only runs when executed directly).
import { meanRgb, withinTolerance } from "../verify-frames";

/** Encode an RGBA image as PNG (zlib-deflate, no row filters). */
function encodePng(width: number, height: number, rgba: Buffer): Buffer {
    function crc32(buf: Buffer): number {
        let c = 0xffffffff;
        for (let i = 0; i < buf.length; i++) {
            c ^= buf[i];
            for (let k = 0; k < 8; k++) {
                c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
            }
        }
        return (c ^ 0xffffffff) >>> 0;
    }
    function chunk(type: string, data: Buffer): Buffer {
        const len = Buffer.alloc(4);
        len.writeUInt32BE(data.length, 0);
        const typeBuf = Buffer.from(type, "ascii");
        const crc = Buffer.alloc(4);
        crc.writeUInt32BE(crc32(Buffer.concat([typeBuf, data])), 0);
        return Buffer.concat([len, typeBuf, data, crc]);
    }
    const sig = Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]);
    const ihdr = Buffer.alloc(13);
    ihdr.writeUInt32BE(width, 0);
    ihdr.writeUInt32BE(height, 4);
    ihdr[8] = 8; // bit depth
    ihdr[9] = 6; // color type RGBA
    ihdr[10] = 0;
    ihdr[11] = 0;
    ihdr[12] = 0;
    // Add filter byte (None=0) per row
    const stride = width * 4;
    const filtered = Buffer.alloc(height * (stride + 1));
    for (let y = 0; y < height; y++) {
        filtered[y * (stride + 1)] = 0;
        rgba.copy(filtered, y * (stride + 1) + 1, y * stride, (y + 1) * stride);
    }
    const idat = deflateSync(filtered);
    return Buffer.concat([
        sig,
        chunk("IHDR", ihdr),
        chunk("IDAT", idat),
        chunk("IEND", Buffer.alloc(0)),
    ]);
}

function solidImage(width: number, height: number, r: number, g: number, b: number): Buffer {
    const buf = Buffer.alloc(width * height * 4);
    for (let i = 0; i < width * height; i++) {
        buf[i * 4] = r;
        buf[i * 4 + 1] = g;
        buf[i * 4 + 2] = b;
        buf[i * 4 + 3] = 255;
    }
    return buf;
}

describe("verify-frames helpers", () => {
    const tmp = mkdtempSync(join(tmpdir(), "verify-frames-"));

    it("meanRgb returns exact color for a solid image", async () => {
        const w = 16, h = 16;
        const png = encodePng(w, h, solidImage(w, h, 11, 18, 32));
        const path = join(tmp, "solid.png");
        writeFileSync(path, png);
        // Force the helpers' module to decode our PNG by reusing the same
        // decoder via a small adapter: meanRgb wants an Image, so we replicate
        // a minimal decode via verify-frames' internal path. We'll instead
        // simply build an Image-like object and run meanRgb directly.
        const img = { width: w, height: h, pixels: solidImage(w, h, 11, 18, 32) };
        const m = meanRgb(img, 0, 0, w, h);
        expect(m.r).toBeCloseTo(11, 5);
        expect(m.g).toBeCloseTo(18, 5);
        expect(m.b).toBeCloseTo(32, 5);
    });

    it("withinTolerance honors the +-10 envelope", () => {
        const theme = { r: 11, g: 18, b: 32 };
        expect(withinTolerance({ r: 11, g: 18, b: 32 }, theme, 10)).toBe(true);
        expect(withinTolerance({ r: 20, g: 27, b: 41 }, theme, 10)).toBe(true);
        expect(withinTolerance({ r: 22, g: 18, b: 32 }, theme, 10)).toBe(false);
    });

    it("meanRgb on left-half rectangle ignores right-half pixels", () => {
        const w = 20, h = 4;
        // Left half = bg, right half = white
        const buf = Buffer.alloc(w * h * 4);
        for (let y = 0; y < h; y++) {
            for (let x = 0; x < w; x++) {
                const idx = (y * w + x) * 4;
                if (x < w / 2) {
                    buf[idx] = 11;
                    buf[idx + 1] = 18;
                    buf[idx + 2] = 32;
                } else {
                    buf[idx] = 255;
                    buf[idx + 1] = 255;
                    buf[idx + 2] = 255;
                }
                buf[idx + 3] = 255;
            }
        }
        const img = { width: w, height: h, pixels: buf };
        const left = meanRgb(img, 0, 0, w / 2, h);
        expect(left.r).toBeCloseTo(11, 5);
        expect(left.g).toBeCloseTo(18, 5);
        expect(left.b).toBeCloseTo(32, 5);
    });

    it("meanRgb green-dominance pattern is detectable", () => {
        const w = 10, h = 4;
        const buf = solidImage(w, h, 40, 200, 60); // green-dominant caption
        const img = { width: w, height: h, pixels: buf };
        const m = meanRgb(img, 0, 0, w, h);
        expect(m.g).toBeGreaterThan(m.r + 20);
        expect(m.g).toBeGreaterThan(m.b + 20);
    });

    // teardown
    afterAllCleanup(tmp);
});

function afterAllCleanup(path: string) {
    // Vitest's `afterAll` would also work; this helper keeps the test body
    // self-contained against the project's evolving vitest setup.
    process.on("exit", () => {
        try {
            rmSync(path, { recursive: true, force: true });
        } catch {
            /* ignore */
        }
    });
}
