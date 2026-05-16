#!/usr/bin/env node
// Walk dist/ recursively, gzip each file, and emit
// ../.omc/research/bundle-size-m1.json.
import { readdirSync, statSync, readFileSync, mkdirSync, writeFileSync } from 'node:fs';
import { join, relative, dirname } from 'node:path';
import { gzipSync } from 'node:zlib';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const webRoot = dirname(__dirname); // .../web
const distDir = join(webRoot, 'dist');
const outPath = join(webRoot, '..', '.omc', 'research', 'bundle-size-m1.json');

function walk(dir) {
  const out = [];
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    const s = statSync(full);
    if (s.isDirectory()) out.push(...walk(full));
    else out.push(full);
  }
  return out;
}

try {
  statSync(distDir);
} catch {
  console.error(`bundle-report: ${distDir} does not exist — skipping.`);
  process.exit(0);
}

const files = walk(distDir);
let totalRaw = 0;
let totalGz = 0;
const fileEntries = files.map((f) => {
  const buf = readFileSync(f);
  const gz = gzipSync(buf);
  const rel = relative(distDir, f);
  // Source maps and Vite manifest are dev/debug artifacts — they ship in dist/
  // but the dashboard binary does not serve sourcemaps (CSP forbids), so they
  // don't count toward the user-facing bundle weight.
  const isShipped = !rel.endsWith('.map') && !rel.includes('manifest.json');
  if (isShipped) {
    totalRaw += buf.length;
    totalGz += gz.length;
  }
  return {
    path: rel,
    kb: +(buf.length / 1024).toFixed(2),
    kb_gz: +(gz.length / 1024).toFixed(2),
    shipped: isShipped,
  };
});
fileEntries.sort((a, b) => b.kb_gz - a.kb_gz);

const report = {
  timestamp: new Date().toISOString(),
  total_kb: +(totalRaw / 1024).toFixed(2),
  total_kb_gz: +(totalGz / 1024).toFixed(2),
  file_count: fileEntries.length,
  shipped_file_count: fileEntries.filter((f) => f.shipped).length,
  files: fileEntries,
};

mkdirSync(dirname(outPath), { recursive: true });
writeFileSync(outPath, JSON.stringify(report, null, 2) + '\n');
console.log(
  `bundle-report: ${fileEntries.length} files, ${report.total_kb} KB raw, ${report.total_kb_gz} KB gzipped → ${outPath}`,
);
