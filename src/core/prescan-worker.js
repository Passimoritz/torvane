'use strict';

// Statische Vorpruefung im eigenen Thread. Sie rechnet bei grossen Projekten viele Sekunden am Stueck. Im Hauptprozess
// wuerde das die ganze Oberflaeche einfrieren, auch das Mausrad, denn dessen Ereignisse laufen durch den Hauptprozess.
//
// Tempo:
//  - Zwischenspeicher je Datei (opts.cache: get/set/flush): unveraenderte Dateien werden nicht neu geprueft.
//  - Viele neue Dateien werden auf mehrere Threads verteilt; die dateiuebergreifenden Code-Regeln laufen
//    gleichzeitig in einem eigenen Thread.

const os = require('os');
const path = require('path');
const { Worker, isMainThread, parentPort, workerData } = require('worker_threads');

if (!isMainThread && workerData && workerData.vigilPrescan) {
  if (workerData.mode === 'scan') {
    const { scanUnits } = require('./prescan');
    parentPort.postMessage({ result: scanUnits(workerData.units, workerData.opts) });
  } else {
    const { runStaticModules } = require('./modules/static');
    const mods = runStaticModules(workerData.units, (p) => parentPort.postMessage({ progress: p }));
    parentPort.postMessage({ result: mods });
  }
}

const PARALLEL_FROM = 400; // ab so vielen neuen Dateien lohnt sich das Aufteilen

// Einen Teil im Thread rechnen; klappt das nicht (z. B. nicht uebertragbare Daten), rechnet der Hauptprozess.
function inWorker(data, fallback, onProgress = () => {}) {
  return new Promise((resolve) => {
    let worker; let settled = false;
    const done = (v) => { if (settled) return; settled = true; try { worker && worker.terminate(); } catch { /* egal */ } resolve(v); };
    const fb = () => { if (settled) return; done(fallback()); };
    try { worker = new Worker(path.join(__dirname, 'prescan-worker.js'), { workerData: { vigilPrescan: true, ...data } }); } catch { fb(); return; }
    worker.on('message', (m) => { if (m.progress) { onProgress(m.progress); return; } if (m.result) done(m.result); });
    worker.on('error', fb);
    worker.on('exit', () => { if (!settled) fb(); });
  });
}

function threadsFor(n) {
  if (n < PARALLEL_FROM) return 1;
  return Math.max(1, Math.min(3, (os.cpus() || []).length - 1));
}

// opts: { customSecrets, disabledRules, cache? }
async function runPrescan(units, opts = {}, onProgress = () => {}) {
  const { scanUnits, mergeUnitResults, cacheKeyFor } = require('./prescan');
  const cache = opts.cache && typeof opts.cache.get === 'function' ? opts.cache : null;
  const base = { customSecrets: opts.customSecrets, disabledRules: opts.disabledRules };
  // 1. Zwischenspeicher: unveraenderte Dateien sofort
  const results = new Array(units.length);
  const fresh = [];
  const keys = [];
  units.forEach((u, i) => {
    const k = cache ? cacheKeyFor(u, base) : null;
    const hit = k ? cache.get(k) : null;
    if (hit && Array.isArray(hit.findings)) results[i] = hit;
    else { fresh.push(i); keys[i] = k; }
  });
  if (cache && fresh.length < units.length) onProgress({ phase: 'prescan', message: `${units.length - fresh.length} unveränderte Datei(en) aus dem Zwischenspeicher` });
  // 2. Neue Dateien in Teile aufteilen, Code-Regeln parallel dazu
  const n = threadsFor(fresh.length);
  const parts = Array.from({ length: n }, (_, p) => fresh.filter((_, j) => j % n === p));
  const [partResults, mods] = await Promise.all([
    Promise.all(parts.map((idx) => {
      const sub = idx.map((i) => units[i]);
      return inWorker({ mode: 'scan', units: sub, opts: base }, () => scanUnits(sub, base)).then((rs) => ({ idx, rs }));
    })),
    inWorker({ mode: 'static', units }, () => require('./modules/static').runStaticModules(units, onProgress), onProgress),
  ]);
  for (const { idx, rs } of partResults) idx.forEach((i, j) => { results[i] = rs[j]; if (cache && keys[i]) cache.set(keys[i], rs[j]); });
  if (cache && typeof cache.flush === 'function') cache.flush();
  return { pre: mergeUnitResults(results), mods, stats: { cached: units.length - fresh.length, threads: n } };
}

module.exports = { runPrescan, PARALLEL_FROM };
