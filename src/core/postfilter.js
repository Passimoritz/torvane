'use strict';

// Nachfilter am Ende jeder Pruefung (in index.finalize), arbeitet auf allen Befunden aller Quellen:
//  1. Ausnahmen direkt im Code:   // torvane-ignore: secret-jwt Testtoken fuer die Anmeldung
//     (auch vigil-ignore; Regel-ID, Praefix wie "secret-" oder *; Begruendung ist Pflicht).
//     In den ersten 10 Zeilen gilt "torvane-ignore-file: <regeln> <Grund>" fuer die ganze Datei.
//  2. Qualitaetsregeln (quality-*) nur, wenn eingeschaltet (Projektdatei oder Einstellung).
//  3. Fremdcode und erzeugte Dateien: Befunde werden zum Hinweis (Geheimnisse und Abhaengigkeiten ausgenommen).
//  4. Projektdatei: abgeschaltete Regeln und feste Schwere je Regel.
//  5. Trefferquote je Regel: haeufig als Fehlalarm markierte Regeln eine Stufe herunter.
//  6. Beleg wortgleich pruefen: steht der zitierte Ausschnitt wirklich in der Datei?

const SEV_DOWN = { critical: 'high', high: 'medium', medium: 'low', low: 'info', info: 'info' };
const IGNORE_RE = /(?:torvane|vigil)-ignore(-file)?\b\s*:?\s*(.*)$/i;

function splitLoc(loc) {
  const m = String(loc || '').replace(/\\/g, '/').match(/^(.*?):(\d+)(?::\d+)?$/);
  return m ? { file: m[1], line: Number(m[2]) } : { file: String(loc || '').replace(/\\/g, '/'), line: 0 };
}

// "secret-jwt,sast-redos Testdaten" -> { rules: [...], reason }
function parseIgnore(rest) {
  const clean = String(rest || '').replace(/\s*(\*\/|-->|#\}|%>)\s*$/, '').trim();
  const first = (clean.match(/^\S+/) || [''])[0];
  const isRules = first === '*' || /^[a-z0-9*][a-z0-9*._-]*-[a-z0-9*._-]*(,[a-z0-9*._-]+)*$/i.test(first);
  const rules = isRules ? first.split(',').filter(Boolean) : ['*'];
  const reason = (isRules ? clean.slice(first.length) : clean).replace(/^\s*(--|—|–|:|-)\s*/, '').trim();
  return { rules, reason };
}
const ruleMatches = (rules, id) => rules.some((r) => r === '*' || r === id || (r.endsWith('*') ? id.startsWith(r.slice(0, -1)) : r.endsWith('-') && id.startsWith(r)));

function inlineIgnoreFor(unit, f) {
  if (!unit || typeof unit.content !== 'string') return null;
  const lines = unit.content.split(/\r?\n/);
  const { line } = splitLoc(f.location);
  const check = (text, fileLevel) => {
    const m = String(text || '').match(IGNORE_RE);
    if (!m || (!!m[1] !== fileLevel)) return null;
    const p = parseIgnore(m[2]);
    return ruleMatches(p.rules, String(f.ruleId || '')) ? p : null;
  };
  if (line > 0) for (const l of [line - 1, line - 2]) { const hit = l >= 0 && check(lines[l], false); if (hit) return hit; }
  for (let i = 0; i < Math.min(10, lines.length); i++) { const hit = check(lines[i], true); if (hit) return hit; }
  return null;
}

// Beleg wortgleich in der Datei? 'found' | 'missing' | null (nicht pruefbar)
const norm = (s) => String(s).replace(/\s+/g, ' ').trim().toLowerCase();
function evidenceCheck(unit, f) {
  const ev = String(f.evidence || '');
  if (!unit || typeof unit.content !== 'string' || ev.length < 6 || /→|\s·\s/.test(ev)) return null;
  const hay = norm(unit.content);
  const parts = ev.split(/\*{2,}REDACTED\*{2,}|…|\.\.\.|,\s+/).map(norm).filter((p) => p.length >= 3);
  if (!parts.length) return null;
  return parts.every((p) => hay.includes(p)) ? 'found' : 'missing';
}

// opts: { project, qualityRules, ruleQuality: { ruleId: { fp, total } } }
function applyPostFilters(findings, units = [], opts = {}) {
  const project = opts.project || null;
  const byLabel = new Map();
  for (const u of units) byLabel.set(String(u.label || '').replace(/\\/g, '/'), u);
  const unitOf = (f) => byLabel.get(splitLoc(f.location).file);
  const qualityOn = !!(opts.qualityRules || (project && project.qualityRules));
  const disabled = new Set(project ? project.disabledRules : []);
  const sevFix = project ? project.severity : {};
  const rq = opts.ruleQuality || {};
  const suppressed = [];
  const notes = [];
  let thirdParty = 0, noReason = 0, droppedQuality = 0, downByQuality = 0, missingQuotes = 0;

  const out = [];
  for (const f0 of findings) {
    let f = f0;
    const id = String(f.ruleId || '');
    if (id && disabled.has(id)) { suppressed.push({ ruleId: id, location: f.location, by: 'project', reason: 'in der Projektdatei abgeschaltet' }); continue; }
    if (/^quality-/.test(id) && !qualityOn) { droppedQuality++; continue; }
    const unit = unitOf(f);
    const ign = inlineIgnoreFor(unit, f);
    if (ign) {
      if (ign.reason) { suppressed.push({ ruleId: id, title: f.title, location: f.location, by: 'inline', reason: ign.reason.slice(0, 300) }); continue; }
      noReason++;
    }
    if (unit && id === 'script-obfuscated' && (unit.devData || /(^|\/)(test|tests|__tests__|spec|e2e|fixtures?)\//i.test(splitLoc(f.location).file)) && f.severity !== 'info') {
      f = { ...f, severityOriginal: f.severity, severity: 'info', devOnly: true };
    }
    if (unit && (unit.vendored || unit.generated) && !['Secrets', 'Dependencies'].includes(f.category) && f.severity !== 'info') {
      f = { ...f, severityOriginal: f.severityOriginal || f.severity, severity: 'info', thirdParty: unit.vendored ? 'vendored' : 'generated' };
      thirdParty++;
    }
    if (id && sevFix[id]) f = { ...f, severityOriginal: f.severityOriginal || f.severity, severity: sevFix[id] };
    const q = rq[id];
    if (q && q.fp >= 3 && q.total > 0 && q.fp / q.total >= 0.5 && f.severity !== 'info' && !(id && sevFix[id])) {
      f = { ...f, severityOriginal: f.severityOriginal || f.severity, severity: SEV_DOWN[f.severity] || f.severity, ruleQuality: { fp: q.fp, total: q.total } };
      downByQuality++;
    }
    const ec = evidenceCheck(unit, f);
    if (ec) {
      f = { ...f, evidenceCheck: ec };
      // KI-Befund mit erfundenem Zitat: nicht loeschen, aber deutlich abwerten
      if (ec === 'missing' && (f.sources || [f.source]).every((s) => s === 'ai')) {
        f = { ...f, assurance: 'unverified', confidence: 'low', severityOriginal: f.severityOriginal || f.severity, severity: SEV_DOWN[f.severity] || f.severity };
        missingQuotes++;
      }
    }
    out.push(f);
  }
  if (suppressed.length) notes.push(`${suppressed.length} Befund(e) per Ausnahme ausgeblendet (im Code oder in der Projektdatei, mit Begründung).`);
  if (noReason) notes.push(`${noReason} Ausnahme(n) im Code ohne Begründung nicht übernommen – bitte einen Grund hinter die Regel schreiben.`);
  if (droppedQuality) notes.push(`${droppedQuality} Qualitäts-Hinweis(e) ausgeblendet (lange/verzweigte Funktionen, Kopien). Einschalten mit qualityRules: true in torvane.yml.`);
  if (thirdParty) notes.push(`${thirdParty} Befund(e) in Fremdcode oder erzeugten Dateien zum Hinweis herabgestuft.`);
  if (downByQuality) notes.push(`${downByQuality} Befund(e) herabgestuft, weil ihre Regel oft als Fehlalarm markiert wurde.`);
  if (missingQuotes) notes.push(`${missingQuotes} KI-Befund(e) herabgestuft: der zitierte Beleg steht so nicht in der Datei.`);
  return { findings: out, suppressed, notes };
}

module.exports = { applyPostFilters, parseIgnore, inlineIgnoreFor, evidenceCheck };
