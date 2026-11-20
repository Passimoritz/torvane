'use strict';

// Entwickler-Ablauf: Torvane dort, wo Code entsteht.
//  - stagedSnapshot: nur die gestagten Dateien (git diff --cached) in einen Temp-Ordner, fuer pre-commit
//  - installHook:    .git/hooks/pre-commit, das vor jedem Commit die gestagten Dateien prueft
//  - watchFolder:    prueft beim Speichern erneut und meldet nur, was neu dazukam oder behoben ist
//  - issuePayloads/createIssues:  Befunde als GitHub-Issues, ohne Doppelte (Marker mit Fingerabdruck)
//  - changedLines/reviewComments/postReview: Kommentare im Pull Request nur an geaenderten Zeilen
// Netzwerkzugriffe (GitHub-API) laufen nur auf ausdruecklichen Aufruf der Kommandozeile.

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { execFileSync } = require('child_process');
const { NAMES: PROJECT_FILES } = require('./projectconfig');

const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info'];
const atLeast = (sev, min) => SEV_ORDER.indexOf(sev) <= SEV_ORDER.indexOf(min || 'low');
const git = (cwd, args, opts = {}) => execFileSync('git', args, { cwd, maxBuffer: 256 * 1024 * 1024, windowsHide: true, ...opts });

// --- pre-commit ---------------------------------------------------------------
// Gestagte Fassung aller hinzugefuegten/geaenderten Dateien in einen Temp-Ordner (gleiche relative Pfade).
function stagedSnapshot(cwd = process.cwd()) {
  const root = git(cwd, ['rev-parse', '--show-toplevel']).toString().trim();
  const names = git(root, ['diff', '--cached', '--name-only', '--diff-filter=ACMR', '-z']).toString().split('\0').filter(Boolean);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'torvane-staged-'));
  const snap = path.join(dir, path.basename(root));
  fs.mkdirSync(snap, { recursive: true });
  for (const n of names) {
    const dest = path.join(snap, n);
    fs.mkdirSync(path.dirname(dest), { recursive: true });
    fs.writeFileSync(dest, git(root, ['show', `:${n}`]));
  }
  // Projektdatei und .vigilignore gelten auch fuer den Hook
  for (const f of [...PROJECT_FILES, '.vigilignore']) {
    if (fs.existsSync(path.join(root, f)) && !names.includes(f)) fs.copyFileSync(path.join(root, f), path.join(snap, f));
  }
  return { root, dir, snapshot: snap, files: names };
}

function installHook(cwd = process.cwd(), { failOn = 'high', cliPath = path.join(__dirname, '..', 'cli.js') } = {}) {
  const root = git(cwd, ['rev-parse', '--show-toplevel']).toString().trim();
  const hooks = path.join(root, '.git', 'hooks');
  const file = path.join(hooks, 'pre-commit');
  if (fs.existsSync(file) && !/torvane/i.test(fs.readFileSync(file, 'utf8'))) return { ok: false, file, error: 'Es gibt schon einen eigenen pre-commit-Hook. Bitte die Zeile von Hand ergänzen.' };
  const script = `#!/bin/sh\n# torvane: prueft die gestagten Dateien vor jedem Commit (Regeln, ohne KI)\nnode "${cliPath.replace(/\\/g, '/')}" --staged --fail-on ${failOn} || {\n  echo "Torvane hat Befunde ab \\"${failOn}\\" gefunden. Beheben oder mit torvane-ignore begründen (git commit --no-verify umgeht die Prüfung)."\n  exit 1\n}\n`;
  fs.mkdirSync(hooks, { recursive: true });
  fs.writeFileSync(file, script, { mode: 0o755 });
  return { ok: true, file };
}

// --- Pruefen beim Speichern -------------------------------------------------------
const keyOf = (f) => `${f.ruleId}|${f.location}|${f.title}`;
function diffFindings(before, after) {
  const a = new Map(before.map((f) => [keyOf(f), f]));
  const b = new Map(after.map((f) => [keyOf(f), f]));
  return { added: after.filter((f) => !a.has(keyOf(f))), resolved: before.filter((f) => !b.has(keyOf(f))) };
}

// run: async () => findings[]; onChange({ added, resolved, total }). Gibt eine stop()-Funktion zurueck.
function watchFolder(dir, { run, onChange, debounceMs = 800, ignore = /(^|[\\/])(node_modules|\.git|dist|build|out|coverage)([\\/]|$)/ } = {}) {
  let last = null, timer = null, busy = false, again = false;
  const tick = async () => {
    if (busy) { again = true; return; }
    busy = true;
    try {
      const now = await run();
      if (last) { const d = diffFindings(last, now); if (d.added.length || d.resolved.length) onChange({ ...d, total: now.length }); }
      else onChange({ added: [], resolved: [], total: now.length, initial: true });
      last = now;
    } finally { busy = false; if (again) { again = false; tick(); } }
  };
  const w = fs.watch(dir, { recursive: true }, (_e, file) => {
    if (file && ignore.test(String(file))) return;
    clearTimeout(timer); timer = setTimeout(tick, debounceMs);
  });
  tick();
  return () => { clearTimeout(timer); w.close(); };
}

// --- GitHub-Issues ---------------------------------------------------------------
const fp = (f) => crypto.createHash('sha1').update(`${f.ruleId}|${String(f.location || '').replace(/:\d+$/, '')}|${f.title}`).digest('hex').slice(0, 16);
const SEV_DE = { critical: 'kritisch', high: 'hoch', medium: 'mittel', low: 'niedrig', info: 'Hinweis' };

function issuePayloads(findings, { minSeverity = 'high' } = {}) {
  return findings.filter((f) => !f.suppressed && atLeast(f.severity, minSeverity)).map((f) => {
    const marker = `<!-- torvane:fp=${fp(f)} -->`;
    const body = [
      `**Schwere:** ${SEV_DE[f.severity] || f.severity} · **Kategorie:** ${f.category || '-'} · **Regel:** \`${f.ruleId || '-'}\``,
      f.location ? `**Fundstelle:** \`${f.location}\`` : '',
      '', f.description || '',
      f.impact ? `\n**Wie gefährlich:** ${f.impact}` : '',
      f.remediation ? `\n**So behebst du es:** ${f.remediation}` : '',
      f.evidence ? `\n\`\`\`\n${String(f.evidence).slice(0, 400)}\n\`\`\`` : '',
      '', `_Gefunden von Torvane._ ${marker}`,
    ].filter((x) => x !== '').join('\n');
    return { title: `[Torvane] ${f.title}`.slice(0, 250), body, labels: ['torvane', `severity:${f.severity}`], marker };
  });
}

async function gh(token, method, url, body, fetchImpl = fetch) {
  const res = await fetchImpl(`https://api.github.com${url}`, {
    method, headers: { Authorization: `Bearer ${token}`, Accept: 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28', 'User-Agent': 'torvane-cli', ...(body ? { 'Content-Type': 'application/json' } : {}) },
    ...(body ? { body: JSON.stringify(body) } : {}),
  });
  const text = await res.text();
  if (!res.ok) throw new Error(`GitHub ${res.status}: ${text.slice(0, 200)}`);
  return text ? JSON.parse(text) : null;
}

function tokenFromEnv() {
  if (process.env.GITHUB_TOKEN || process.env.GH_TOKEN) return process.env.GITHUB_TOKEN || process.env.GH_TOKEN;
  try { return execFileSync('gh', ['auth', 'token'], { windowsHide: true }).toString().trim(); } catch { return ''; }
}

// Legt nur Issues an, deren Marker noch in keinem (auch geschlossenen) Torvane-Issue steht.
async function createIssues(repo, payloads, { token = tokenFromEnv(), dryRun = false, fetchImpl } = {}) {
  if (!/^[\w.-]+\/[\w.-]+$/.test(repo)) throw new Error('Repository als owner/name angeben.');
  const existing = new Set();
  if (token) {
    for (let page = 1; page <= 10; page++) {
      const list = await gh(token, 'GET', `/repos/${repo}/issues?state=all&labels=torvane&per_page=100&page=${page}`, null, fetchImpl);
      for (const i of list || []) { const m = String(i.body || '').match(/torvane:fp=([0-9a-f]{16})/); if (m) existing.add(m[1]); }
      if (!list || list.length < 100) break;
    }
  } else if (!dryRun) throw new Error('Kein GitHub-Token gefunden (GITHUB_TOKEN oder gh auth login).');
  const todo = payloads.filter((p) => !existing.has(p.marker.match(/fp=([0-9a-f]{16})/)[1]));
  const created = [];
  if (!dryRun) for (const p of todo) created.push(await gh(token, 'POST', `/repos/${repo}/issues`, { title: p.title, body: p.body, labels: p.labels }, fetchImpl));
  return { planned: todo, skipped: payloads.length - todo.length, created: created.map((c) => c && c.html_url) };
}

// --- Kommentare im Pull Request ----------------------------------------------------
// Unified Diff (git diff -U0 base...head) -> { 'pfad': Set(neue Zeilennummern) }
function changedLines(diffText) {
  const out = {}; let file = null;
  for (const line of String(diffText).split('\n')) {
    if (line.startsWith('+++ ')) { file = line.slice(4).replace(/^b\//, '').trim(); if (file === '/dev/null') file = null; else out[file] = out[file] || new Set(); continue; }
    const m = line.match(/^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@/);
    if (m && file) { const start = Number(m[1]); const n = m[2] == null ? 1 : Number(m[2]); for (let i = 0; i < n; i++) out[file].add(start + i); }
  }
  return out;
}

// Befund-Ort "projekt/pfad/datei.js:12" -> relativer Pfad im Repo (der Ordnername der Pruefung wird abgeschnitten)
function repoPath(location, rootName) {
  const m = String(location || '').replace(/\\/g, '/').match(/^(.*?):(\d+)$/);
  if (!m) return null;
  let p = m[1];
  if (rootName && p.startsWith(rootName + '/')) p = p.slice(rootName.length + 1);
  return { path: p, line: Number(m[2]) };
}

function reviewComments(findings, changed, { rootName = '', minSeverity = 'medium', max = 30 } = {}) {
  const out = [];
  for (const f of findings) {
    if (f.suppressed || !atLeast(f.severity, minSeverity)) continue;
    const loc = repoPath(f.location, rootName);
    if (!loc || !changed[loc.path] || !changed[loc.path].has(loc.line)) continue;
    out.push({ path: loc.path, line: loc.line, side: 'RIGHT', body: `**Torvane (${SEV_DE[f.severity] || f.severity}): ${f.title}**\n\n${f.description || ''}${f.remediation ? `\n\n**So behebst du es:** ${f.remediation}` : ''}` });
    if (out.length >= max) break;
  }
  return out;
}

async function postReview({ repo, pr, commitId, comments, token = tokenFromEnv(), fetchImpl }) {
  if (!comments.length) return { posted: 0 };
  const body = `Torvane hat ${comments.length} Befund(e) an geänderten Zeilen gefunden.`;
  await gh(token, 'POST', `/repos/${repo}/pulls/${pr}/reviews`, { commit_id: commitId, event: 'COMMENT', body, comments }, fetchImpl);
  return { posted: comments.length };
}

module.exports = { stagedSnapshot, installHook, watchFolder, diffFindings, issuePayloads, createIssues, changedLines, repoPath, reviewComments, postReview, tokenFromEnv };
