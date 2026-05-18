#!/usr/bin/env node
// check-build.mjs — post-build SPA smoke gate (plan §3.1 B1 mechanism).
// Spawns `vite preview`, polls readiness (modeled on demo/capture/lib.sh:371-379),
// GETs index.html, asserts <div id="app"> present + lifecycle_function_unavailable absent.
// Handles SIGTERM + EXIT trap so no orphan preview process is left behind.
// Exit 0: "OK: SPA renders without server lifecycle error"
// Exit 1: diagnostic line to stderr (MISSING_APP_DIV or LIFECYCLE_ERROR_DETECTED)

import { spawn } from 'node:child_process';
import { request } from 'node:http';

const PORT = 4173;
const HOST = '127.0.0.1';
const BASE_URL = `http://${HOST}:${PORT}/`;

let previewProc = null;

function cleanup() {
  if (previewProc) {
    try { previewProc.kill('SIGTERM'); } catch (_) {}
    previewProc = null;
  }
}

process.on('SIGTERM', cleanup);
process.on('exit', cleanup);

function httpGet(url, timeoutMs) {
  return new Promise((resolve, reject) => {
    const req = request(url, { timeout: timeoutMs }, (res) => {
      let body = '';
      res.on('data', (chunk) => { body += chunk; });
      res.on('end', () => resolve({ status: res.statusCode, body }));
    });
    req.on('timeout', () => { req.destroy(); reject(new Error('timeout')); });
    req.on('error', reject);
    req.end();
  });
}

function sleep(ms) { return new Promise((r) => setTimeout(r, ms)); }

// Spawn vite preview after vite build completes.
previewProc = spawn('npx', ['vite', 'preview', '--port', String(PORT), '--host', HOST], {
  stdio: ['ignore', 'pipe', 'pipe'],
  detached: false,
});
previewProc.on('error', (err) => {
  process.stderr.write(`check-build: failed to start vite preview: ${err.message}\n`);
  process.exit(1);
});

// Readiness probe: up to 60 × 0.5s = 30s (mirrors demo/capture/lib.sh:371-374).
let ready = false;
for (let i = 0; i < 60; i++) {
  await sleep(500);
  try {
    const r = await httpGet(BASE_URL, 2000);
    if (r.status === 200) { ready = true; break; }
  } catch (_) { /* not ready yet */ }
}

if (!ready) {
  process.stderr.write(`check-build: vite preview did not become ready at :${PORT} within 30s\n`);
  cleanup();
  process.exit(1);
}

// Fetch index and apply exit-1 grep semantics (plan §4.2 AC-VFY-1.3).
let body = '';
try {
  const r = await httpGet(BASE_URL, 5000);
  body = r.body;
} catch (err) {
  process.stderr.write(`check-build: failed to fetch index: ${err.message}\n`);
  cleanup();
  process.exit(1);
}

cleanup();

if (!body.includes('<div id="app">')) {
  process.stderr.write('MISSING_APP_DIV\n');
  process.exit(1);
}
if (body.includes('lifecycle_function_unavailable')) {
  process.stderr.write('LIFECYCLE_ERROR_DETECTED\n');
  process.exit(1);
}

console.log('OK: SPA renders without server lifecycle error');
