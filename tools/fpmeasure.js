'use strict';

// Fehlalarm-Messung: prueft saubere, verbreitete Pakete aus dem eigenen node_modules (Versionen ueber
// package-lock fest) ohne KI und vergleicht die ernsten Treffer (kritisch/hoch/mittel) je Regel mit
// bench/fp-budget.json. Wird eine Regel lauter als erlaubt, endet der Lauf mit Exit-Code 1.
//
//   npm run fp              messen und gegen das Budget pruefen
//   npm run fp -- --update  Budget auf den aktuellen Stand setzen (nach bewusster Aenderung)
//
// Gegenstueck zu npm run bench: der Benchmark misst, ob echte Luecken gefunden werden,
// diese Messung, ob sauberer Code ruhig bleibt.

const fs = require('fs');
const path = require('path');
const { ingestTargets } = require('../src/core/ingest');
const { prescan } = require('../src/core/prescan');
const { runStaticModules } = require('../src/core/modules/static');
const { dedupeFindings } = require('../src/core/schema');
const { applyPostFilters } = require('../src/core/postfilter');

const ROOT = path.join(__dirname, '..');
const BUDGET = path.join(ROOT, 'bench', 'fp-budget.json');
const CORPUS = ['undici', 'ajv', 'zod', 'adm-zip', 'socks', 'js-yaml', 'semver', 'app-builder-lib', 'builder-util', '@electron', 'ejs', 'tar', 'cross-spawn', 'commander', 'debug', 'minimatch', 'glob', 'fs-extra', 'form-data', 'dotenv'];
const SERIOUS = new Set(['critical', 'high', 'medium']);

(async () => {
  const update = process.argv.includes('--update');
  const counts = {};
  let total = 0, files = 0;
  const examples = {};
  for (const pkg of CORPUS) {
    const dir = path.join(ROOT, 'node_modules', pkg);
    if (!fs.existsSync(dir)) continue;
    const ing = await ingestTargets([{ type: 'path', value: dir }]);
    files += ing.units.length;
    const pre = prescan(ing.units, {});
    const mods = runStaticModules(ing.units, () => {});
    const { findings } = applyPostFilters(dedupeFindings([...pre.findings, ...mods.findings, ...(ing.findings || [])]), ing.units, { project: ing.project });
    for (const f of findings) {
      if (!SERIOUS.has(f.severity) || f.devOnly) continue;
      counts[f.ruleId] = (counts[f.ruleId] || 0) + 1;
      total++;
      (examples[f.ruleId] = examples[f.ruleId] || []).length < 3 && examples[f.ruleId].push(f.location);
    }
  }
  console.log(`Fehlalarm-Messung: ${files} Dateien aus ${CORPUS.length} sauberen Paketen, ${total} ernste Treffer.`);
  const rows = Object.entries(counts).sort((a, b) => b[1] - a[1]);
  for (const [id, n] of rows) console.log(`  ${String(n).padStart(4)}  ${id}   z. B. ${examples[id].join(', ')}`);

  if (update) {
    fs.writeFileSync(BUDGET, JSON.stringify({ note: 'Obergrenze ernster Treffer je Regel auf sauberem Code (npm run fp). Nur bewusst erhöhen.', total, rules: Object.fromEntries(rows) }, null, 2) + '\n');
    console.log(`Budget gespeichert: ${path.relative(ROOT, BUDGET)}`);
    return;
  }
  let budget = { total: 0, rules: {} };
  try { budget = JSON.parse(fs.readFileSync(BUDGET, 'utf8')); } catch { console.error('Kein Budget gefunden – einmal mit --update anlegen.'); process.exit(1); }
  const over = rows.filter(([id, n]) => n > (budget.rules[id] || 0));
  if (over.length) {
    console.error('\nLauter als erlaubt:');
    for (const [id, n] of over) console.error(`  ${id}: ${n} statt höchstens ${budget.rules[id] || 0}`);
    process.exit(1);
  }
  console.log(`OK – keine Regel über dem Budget (gesamt ${total}, erlaubt ${budget.total}).`);
})().catch((e) => { console.error(e); process.exit(1); });
