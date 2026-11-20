'use strict';

// Vigil-Oberfläche, Teil 1/9: Zustand, Hilfsfunktionen, Ziele, bekannte Ziele, Drag & Drop, Start der Analyse.
// Die Oberfläche ist auf mehrere klassische Skripte in src/ui/app/ verteilt (Reihenfolge siehe index.html).

const $ = (id) => document.getElementById(id);
const uiLocale = () => (typeof state !== 'undefined' && state.config && state.config.lang === 'de' ? 'de-DE' : 'en-GB');
const esc = (s) => String(s == null ? '' : s).replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));

const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info'];
const SEV_LABEL = { critical: 'Kritisch', high: 'Hoch', medium: 'Mittel', low: 'Niedrig', info: 'Hinweis' };
// Kurzformen fuer Farbklassen (c-*, sb-*, --sev-*). Nie "info": das kollidiert mit UI-Klassen.
const SEV_CLS = { critical: 'crit', high: 'high', medium: 'med', low: 'low', info: 'note' };
const SEV_HELP = {
  critical: 'Sofort beheben – leicht ausnutzbar, großer Schaden möglich.',
  high: 'Zeitnah beheben – ernstes Risiko.',
  medium: 'Beheben, wenn möglich – mittleres Risiko.',
  low: 'Kleineres Risiko – gut, es zu beheben.',
  info: 'Nur ein Hinweis, kein akutes Risiko.',
};
const PHASES = [
  { key: 'ingest', label: 'Sammeln' },
  { key: 'prescan', label: 'Vorprüfung' },
  { key: 'cve', label: 'Schwachstellen-DB' },
  { key: 'webscan', label: 'Server-Checks' },
  { key: 'active', label: 'Aktiv-Scan' },
  { key: 'analyze', label: 'KI-Analyse' },
  { key: 'validate', label: 'Gegenprüfung' },
  { key: 'done', label: 'Fertig' },
];

const state = { targets: [], providers: [], config: null, lastFindings: [], lastResult: null, filter: 'all', query: '', onlyNew: false, onlyProven: false, showSuppressed: false, running: false };
let RULE_NAMES = null; // Namen der eingebauten Regeln (lazy via IPC)

// --- Ziele --------------------------------------------------------------
const KIND_LABEL = { path: 'Datei/Ordner', url: 'Webadresse', endpoint: 'Server', image: 'Container-Image', system: 'System' };
const SYSTEM_LABEL = { windows: 'Dieser Windows-PC', docker: 'Laufende Docker-Container', aws: 'AWS-Konto', azure: 'Azure-Abonnement', gcp: 'Google-Cloud-Projekt',
  winapps: 'Installierte Programme', browserext: 'Browser-Erweiterungen', backup: 'Datensicherung (Windows)', macos: 'Dieser Mac', router: 'Router (Standard-Gateway)', lan: 'Geräte im lokalen Netz', linuxssh: 'Linux-Server (SSH)', dbdirect: 'Datenbanken', k8s: 'Kubernetes-Cluster (kubectl)', iam: 'Cloud-Berechtigungen (IAM)', cicd: 'GitHub / GitLab / Azure DevOps', m365: 'Microsoft 365 / Google Workspace', hosting: 'Cloudflare, Hetzner, DigitalOcean, Vercel, Netlify', hibp: 'Datenlecks der Domain (HIBP)' };
const SYSTEM_RE = new RegExp(`^system:(${Object.keys(SYSTEM_LABEL).join('|')})$`, 'i');
function addTarget(type, value, authorized = false) {
  if (!value) return;
  if (state.targets.some((t) => t.type === type && t.value === value)) return;
  state.targets.push({ type, value, authorized });
  renderTargets();
}
// --- Bekannte & vertraute Ziele ---------------------------------------------
// Quelle: alle bisher geprueften Ziele (Befund-Speicher) plus die Freigabeliste.
// "Vertraut" = Host steht auf der Freigabeliste -> Pruefung ohne erneute Rueckfrage.
const known = { list: [], open: false, filter: 'all', q: '' };
const allowMatches = (e, host) => (e.startsWith('*.') ? host === e.slice(2) || host.endsWith(e.slice(1)) : host === e || host.endsWith('.' + e));
async function loadKnown() {
  let targets = [];
  try { targets = ((await window.vigil.dashboard({ limit: 1 })).stats || {}).targets || []; } catch { /* Vorschau */ }
  const items = targets.filter((t) => !t.hiddenFromPicker).map((t) => {
    const host = t.type === 'url' || t.type === 'endpoint' ? hostOfTarget({ type: t.type, value: t.identifier }) : '';
    return { id: t.id, type: t.type, value: t.identifier, name: t.type === 'system' ? SYSTEM_LABEL[t.identifier] || t.name : t.type === 'url' ? String(t.identifier).replace(/^https?:\/\//, '').replace(/\/$/, '') : t.name, host, trusted: !!host && isAllowlisted(host), verified: !!t.ownershipVerified, lastScanAt: t.lastScanAt, open: t.open ? t.open.total : 0 };
  });
  // Freigaben, zu denen es noch keinen Lauf gibt
  for (const e of state.config.allowlist || []) {
    if (items.some((i) => i.host && allowMatches(e, i.host))) continue;
    const h = e.replace(/^\*\./, '');
    items.push({ id: null, type: 'url', value: 'https://' + h, name: e, host: h, trusted: true, verified: false, lastScanAt: null, open: 0, allowOnly: true });
  }
  known.list = items;
  renderKnown();
}
function renderKnown() {
  const box = $('knownBox');
  box.hidden = known.list.length === 0;
  $('knownCount').textContent = known.list.length;
  const nTrusted = known.list.filter((k) => k.trusted).length;
  $('knownHint').textContent = nTrusted ? `${nTrusted} vertraut` : '';
  $('knownToggle').setAttribute('aria-expanded', String(known.open));
  $('knownPanel').hidden = !known.open;
  box.classList.toggle('open', known.open);
  $('knownPanel').querySelectorAll('[data-kf]').forEach((b) => b.classList.toggle('active', b.dataset.kf === known.filter));
  const q = known.q.toLowerCase();
  const rows = known.list.filter((k) => (known.filter === 'all' || k.trusted) && (!q || `${k.name} ${k.value}`.toLowerCase().includes(q)));
  const inList = (k) => state.targets.some((t) => t.type === k.type && t.value === k.value);
  $('knownList').innerHTML = rows.length ? rows.map((k) => {
    const i = known.list.indexOf(k);
    const added = inList(k);
    return `<li class="known-row${added ? ' added' : ''}">
      <button type="button" class="known-main" data-add="${i}" ${added ? 'disabled' : ''} title="${esc(k.value)}">
        <span class="t-kind ${k.type}">${KIND_LABEL[k.type] || k.type}</span>
        <span class="known-name">${esc(k.name)}</span>
        ${k.trusted ? '<span class="badge trust" title="Wird ohne erneute Rückfrage geprüft">✓ vertraut</span>' : ''}
        ${k.verified ? '<span class="badge verified" title="Domain-Besitz nachgewiesen – tiefe Prüfungen erlaubt">Domain nachgewiesen</span>' : ''}
        <span class="known-meta muted small">${added ? 'in der Prüfliste' : k.lastScanAt ? `zuletzt ${esc(fmtDate(k.lastScanAt))}${k.open ? ` · ${k.open} offen` : ''}` : 'noch nicht geprüft'}</span>
      </button>
      <span class="known-actions">
        ${k.trusted || k.verified ? `<button type="button" class="btn tiny ghost" data-untrust="${i}">Vertrauen entziehen</button>` : ''}
        ${k.id ? `<button type="button" class="btn tiny ghost" data-hide="${i}" title="Nur aus dieser Liste entfernen">Ausblenden</button>` : ''}
      </span>
    </li>`;
  }).join('') : `<li class="muted small known-empty">${known.filter === 'trusted' ? 'Keine vertrauten Ziele.' : 'Nichts gefunden.'}</li>`;
}
async function untrustKnown(k) {
  const entries = (state.config.allowlist || []).filter((e) => k.host && allowMatches(e, k.host));
  const what = entries.length ? `Freigabe ${entries.join(', ')}` : 'Domain-Nachweis';
  if (!confirm(`${k.name} nicht mehr vertrauen?\n\nEntfernt: ${what}.${k.verified ? '\nDer Domain-Nachweis wird ebenfalls zurückgenommen – tiefe Prüfungen brauchen dann einen neuen Nachweis.' : ''}\nBeim nächsten Prüfen fragt Vigil wieder nach der Berechtigung.`)) return;
  state.config.allowlist = (state.config.allowlist || []).filter((e) => !entries.includes(e));
  await saveCfg();
  if (k.id && k.verified) { try { await window.vigil.setTargetMeta(k.id, { ownershipVerified: false }); } catch { /* egal */ } }
  // Bereits in der Pruefliste: herausnehmen – zum Pruefen muss die Berechtigung neu bestaetigt werden
  const before = state.targets.length;
  state.targets = state.targets.filter((t) => !((t.type === 'url' || t.type === 'endpoint') && hostOfTarget(t) === k.host));
  renderTargets();
  toast(`${k.name} wird nicht mehr automatisch vertraut${state.targets.length < before ? ' – aus der Prüfliste genommen' : ''}`, 'ok');
  loadKnown();
}
function setupKnown() {
  $('knownToggle').onclick = () => { known.open = !known.open; renderKnown(); if (known.open) $('knownSearch').focus(); };
  $('knownSearch').addEventListener('input', () => { known.q = $('knownSearch').value; renderKnown(); });
  $('knownPanel').querySelectorAll('[data-kf]').forEach((b) => b.onclick = () => { known.filter = b.dataset.kf; renderKnown(); });
  $('knownList').addEventListener('click', async (e) => {
    const b = e.target.closest('button');
    if (!b) return;
    const k = known.list[Number(b.dataset.add ?? b.dataset.untrust ?? b.dataset.hide)];
    if (!k) return;
    if (b.dataset.add != null) { addTarget(k.type, k.value, k.trusted); toast(`${k.name} zur Prüfliste hinzugefügt`, 'ok'); }
    else if (b.dataset.untrust != null) untrustKnown(k);
    else if (b.dataset.hide != null) { await window.vigil.setTargetMeta(k.id, { hiddenFromPicker: true }); toast(`${k.name} ausgeblendet`, 'ok'); loadKnown(); }
  });
  loadKnown();
}

function renderTargets() {
  const ul = $('targetList');
  ul.innerHTML = '';
  state.targets.forEach((t, i) => {
    const li = document.createElement('li');
    li.innerHTML = `<span class="t-kind ${t.type}">${KIND_LABEL[t.type]}</span><span class="t-val" title="${esc(t.value)}">${esc(t.type === 'system' ? SYSTEM_LABEL[t.value] || t.value : t.value)}</span>`;
    const rm = document.createElement('button');
    rm.className = 't-rm'; rm.textContent = '✕'; rm.setAttribute('aria-label', 'Entfernen');
    rm.onclick = () => { state.targets.splice(i, 1); renderTargets(); };
    li.appendChild(rm);
    ul.appendChild(li);
  });
  document.querySelectorAll('.sys-chip').forEach((b) => b.classList.toggle('on', state.targets.some((t) => t.type === 'system' && t.value === b.dataset.system)));
  $('targetCount').textContent = state.targets.length;
  { const n = state.targets.filter((t) => t.type === 'system').length; const c = $('sysCount'); if (c) { c.textContent = n; c.hidden = !n; } }
  $('targets').hidden = state.targets.length === 0;
  if (known.list.length) renderKnown();
  updateRunState();
}

// Freitext deuten: lokaler Pfad, Webadresse, Container-Image oder Server (IP/Host).
function classifyInput(v) {
  if (/^image:/i.test(v)) return { type: 'image', value: v.slice(6).trim() };
  if (SYSTEM_RE.test(v)) return { type: 'system', value: v.slice(7).toLowerCase() };
  if (/^https?:\/\//i.test(v)) return { type: 'url', value: v };
  if (/^[a-z]:[\\/]|^\\\\|^\/|^\.{1,2}[\\/]|^~[\\/]/i.test(v)) return { type: 'path', value: v };
  // Image mit Tag (nginx:1.25, ghcr.io/org/app:2.1) oder Digest – ein reiner Zahlen-"Tag" ist ein Port.
  const img = v.match(/^[a-z0-9][a-z0-9._/-]*(?::([\w][\w.-]*)|@sha256:[a-f0-9]{64})$/);
  if (img && !(img[1] && /^\d+$/.test(img[1]))) return { type: 'image', value: v };
  if (/^(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?$|^localhost(?::\d+)?$|^\[?[0-9a-f:]+\]?$|:\d+$/i.test(v)) return { type: 'endpoint', value: v };
  if (/^[\w-]+(\.[\w-]+)+(\/.*)?$/.test(v)) return { type: 'url', value: 'https://' + v };
  return { type: 'endpoint', value: v };
}

// Webadressen und Server brauchen eine Freigabe; steht der Host schon auf der Liste, entfaellt die Bestaetigung.
function hostOfTarget(t) {
  if (t.type === 'url') { try { return new URL(t.value).hostname.toLowerCase(); } catch { return ''; } }
  if (t.type !== 'endpoint') return '';
  const m = t.value.match(/^\[([^\]]+)\]/);
  return (m ? m[1] : t.value.replace(/:\d+$/, '')).toLowerCase();
}
function isAllowlisted(host) {
  return !!host && (state.config.allowlist || []).some((e) => (e.startsWith('*.') ? host.endsWith(e.slice(1)) : host === e || host.endsWith('.' + e)));
}
const needsConfirm = (t) => (t.type === 'url' || t.type === 'endpoint') && !isAllowlisted(hostOfTarget(t));

function onTargetInput() {
  const v = $('targetInput').value.trim();
  const t = v && !/^(https?:\/\/|image:)$/i.test(v) ? classifyInput(v) : null;
  $('targetKind').hidden = !t;
  if (t) $('targetKind').textContent = 'Erkannt: ' + KIND_LABEL[t.type];
  $('authRow').hidden = !(t && needsConfirm(t));
  $('authLabel').textContent = t && t.type === 'url' ? 'Diese Webseite gehört mir bzw. ich darf sie prüfen.' : 'Ich bin berechtigt, diesen Server zu prüfen.';
  $('webNote').hidden = !(t && (t.type === 'url' || t.type === 'endpoint'));
  $('imageNote').hidden = !(t && t.type === 'image');
}
function addTypedTarget() {
  const v = $('targetInput').value.trim();
  if (!v) return;
  const t = classifyInput(v);
  if (needsConfirm(t) && !$('authChk').checked) {
    // Bestaetigung direkt unter dem Feld hervorheben – ein Klick auf „Ja – hinzufügen“ genuegt
    const bar = $('authRow'); bar.hidden = false;
    bar.classList.remove('attention'); void bar.offsetWidth; bar.classList.add('attention');
    $('authYes').focus();
    return;
  }
  addTarget(t.type, t.value, t.type === 'url' || t.type === 'endpoint');
  $('targetInput').value = ''; $('authChk').checked = false; onTargetInput();
}

// Startknopf + Hinweis: sagt immer, was als Naechstes fehlt.
// Dateien/Ordner analysiert die KI. Webadressen und Server nur mit der Einstellung, Images und Systeme nie.
const needsAi = () => state.targets.some((t) => t.type === 'path' || (!!(state.config && state.config.aiForWeb) && (t.type === 'url' || t.type === 'endpoint')));
function updateRunState() {
  if (typeof renderGbRun === 'function') renderGbRun();
  const ready = needsAi() ? aiReady() : { ok: true, label: 'den passiven Checks (ohne KI)' };
  $('runBtn').disabled = state.running || !state.targets.length || !ready.ok;
  if (state.running) return;
  if (!state.targets.length) $('runHint').textContent = 'Füge oben zuerst etwas zur Prüfliste hinzu.';
  else if (!ready.ok) $('runHint').textContent = ready.why;
  else $('runHint').textContent = `Bereit – ${state.targets.length} ${state.targets.length === 1 ? 'Ziel' : 'Ziele'} mit ${ready.label}.`;
  scheduleEstimate(ready.ok && state.targets.length > 0);
  setRunEta();
  updateReady(ready);
  updateStatusBar();
  renderFlow();
}

// --- Gefuehrter Ablauf: Ziel waehlen -> Einstellungen -> Pruefen -> Ergebnis -------------
// Dieselbe Leiste steht ueber "Neue Pruefung" und "Ergebnis"; ein Klick springt zum Schritt.
const FLOW = [
  { key: 'target', label: 'Ziel wählen' },
  { key: 'settings', label: 'Einstellungen' },
  { key: 'run', label: 'Prüfen' },
  { key: 'result', label: 'Ergebnis' },
];
function flowState() {
  const n = state.targets.length;
  const aiOk = !needsAi() || (typeof aiReady === 'function' && aiReady().ok);
  const hasResult = !!state.lastResult;
  // Im Ergebnis beschreibt die Leiste den letzten Lauf, in "Neue Pruefung" den naechsten
  const past = state.running || (state.view === 'results' && hasResult);
  const done = past
    ? { target: true, settings: true, run: !state.running, result: hasResult && !state.running }
    : { target: n > 0, settings: n > 0 && aiOk, run: false, result: false };
  const current = state.running ? 'run' : past ? 'result' : !done.target ? 'target' : !done.settings ? 'settings' : 'run';
  const sub = {
    target: n ? `${n} ${n === 1 ? 'Ziel' : 'Ziele'}` : past ? 'Erledigt' : 'Noch leer',
    settings: past ? 'Erledigt' : !n ? 'Nach dem Ziel' : !needsAi() ? 'Keine KI nötig' : aiOk ? 'KI bereit' : 'KI fehlt',
    run: state.running ? 'Läuft gerade' : past ? 'Erledigt' : done.settings ? 'Startklar' : 'Noch nicht bereit',
    result: hasResult ? `${state.lastFindings.filter((f) => !f.suppressed).length} offen` : 'Noch keins',
  };
  return { done, current, sub };
}
function renderFlow() {
  const s = flowState();
  for (const id of ['flowScan', 'flowResults']) {
    const nav = $(id);
    if (!nav) continue;
    // Nur neu zeichnen, wenn sich etwas aendert: sonst springt die Haken-Animation bei jedem Tastendruck
    const html = `<ol>${FLOW.map((st, i) => {
      const cls = st.key === s.current ? 'current' : s.done[st.key] ? 'done' : '';
      const disabled = st.key === 'result' && !state.lastResult && !state.running;
      return `<li><button type="button" class="flow-step ${cls}" data-flow="${st.key}"${st.key === s.current ? ' aria-current="step"' : ''}${disabled ? ' disabled' : ''}>
        <span class="flow-num" aria-hidden="true">${s.done[st.key] && st.key !== s.current ? '✓' : i + 1}</span>
        <span class="flow-label"><b>${esc(st.label)}</b><small>${esc(s.sub[st.key])}</small></span></button></li>`;
    }).join('')}</ol>`;
    if (nav.dataset.sig === html) continue;
    nav.dataset.sig = html;
    nav.innerHTML = html;
  }
}
function goFlow(key) {
  if (key === 'result') { showView('results'); return; }
  showView('scan');
  const target = { target: 'targetInput', settings: 'aiCard', run: 'runBtn' }[key];
  const el = $(target);
  if (!el) return;
  el.scrollIntoView({ block: key === 'run' ? 'center' : 'start' });
  if (key === 'target') el.focus();
  else if (key === 'run' && !el.disabled) el.focus();
  else { const first = el.querySelector('button, input, select'); if (first) first.focus(); }
}
function setupFlow() {
  for (const id of ['flowScan', 'flowResults']) {
    const nav = $(id);
    if (nav) nav.addEventListener('click', (e) => { const b = e.target.closest('[data-flow]'); if (b && !b.disabled) goFlow(b.dataset.flow); });
  }
  renderFlow();
}

// --- Erklaertexte als (i)-Tooltip -------------------------------------------------------
// Markup: <button class="tip" aria-label="Erklärung"><span class="tip-ico">i</span><span class="tip-body" role="tooltip">…</span></button>
// Zeigen bei Maus und Tastaturfokus, Klick heftet an, Esc schliesst (WCAG 1.4.13). Der Text bleibt im DOM,
// damit die Uebersetzung ihn findet; aria-describedby verbindet ihn mit dem Knopf.
let tipSeq = 0;
function wireTip(t) {
  if (t.dataset.tipReady) return;
  t.dataset.tipReady = '1';
  const body = t.querySelector('.tip-body');
  if (body && !body.id) { body.id = 'tip-' + (++tipSeq); t.setAttribute('aria-describedby', body.id); }
}
function placeTip(t) {
  const body = t.querySelector('.tip-body');
  if (!body) return;
  t.classList.remove('align-start', 'align-end', 'above', 'closed');
  const r = t.getBoundingClientRect();
  const w = Math.min(340, window.innerWidth * 0.78);
  if (r.left + r.width / 2 - w / 2 < 8) t.classList.add('align-start');
  else if (r.left + r.width / 2 + w / 2 > window.innerWidth - 8) t.classList.add('align-end');
  if (r.bottom + 180 > window.innerHeight && r.top > 200) t.classList.add('above');
}
function setupTips(root = document) {
  root.querySelectorAll('.tip').forEach(wireTip);
}
document.addEventListener('mouseover', (e) => { const t = e.target.closest && e.target.closest('.tip'); if (t) { wireTip(t); placeTip(t); } });
document.addEventListener('focusin', (e) => { const t = e.target.closest && e.target.closest('.tip'); if (t) { wireTip(t); placeTip(t); } });
document.addEventListener('click', (e) => {
  const t = e.target.closest && e.target.closest('.tip');
  document.querySelectorAll('.tip.open').forEach((o) => { if (o !== t) o.classList.remove('open'); });
  if (!t) return;
  e.preventDefault(); e.stopPropagation();
  wireTip(t); placeTip(t);
  t.classList.toggle('open');
}, true);
document.addEventListener('keydown', (e) => {
  if (e.key !== 'Escape') return;
  const open = document.querySelectorAll('.tip.open, .tip:hover, .tip:focus-visible');
  if (!open.length) return;
  open.forEach((t) => { t.classList.remove('open'); t.classList.add('closed'); });
  e.stopPropagation();
}, true);
document.addEventListener('mouseout', (e) => { const t = e.target.closest && e.target.closest('.tip'); if (t && !t.contains(e.relatedTarget)) t.classList.remove('closed'); });
document.addEventListener('focusout', (e) => { const t = e.target.closest && e.target.closest('.tip'); if (t) t.classList.remove('closed', 'open'); });

// --- Drag & Drop --------------------------------------------------------
function setupDropzone() {
  const dz = $('dropzone');
  ['dragenter', 'dragover'].forEach((ev) => dz.addEventListener(ev, (e) => { e.preventDefault(); dz.classList.add('drag'); }));
  ['dragleave', 'drop'].forEach((ev) => dz.addEventListener(ev, (e) => { e.preventDefault(); dz.classList.remove('drag'); }));
  dz.addEventListener('drop', (e) => {
    let added = 0;
    for (const f of Array.from(e.dataTransfer.files || [])) {
      const p = window.vigil.pathForFile(f);
      if (p) { addTarget('path', p); added++; }
    }
    if (!added) flash('Konnte die Pfade nicht lesen – nutze die Auswahl-Buttons.');
  });
  // Schnellstart-Kacheln fuer Webseite/Image: Eingabefeld mit passendem Anfang fuellen
  // System-Pruefungen direkt zur Liste hinzufuegen bzw. wieder entfernen
  // macOS-Pruefung nur auf einem Mac anbieten
  const macChip = document.querySelector('.sys-chip[data-system="macos"]');
  if (macChip) macChip.hidden = !/Mac/i.test(navigator.platform || navigator.userAgent || '');
  document.querySelectorAll('.sys-chip').forEach((b) => b.addEventListener('click', () => {
    const v = b.dataset.system;
    const i = state.targets.findIndex((t) => t.type === 'system' && t.value === v);
    if (i >= 0) state.targets.splice(i, 1); else state.targets.push({ type: 'system', value: v });
    renderTargets();
  }));
  dz.querySelectorAll('.quick-tile[data-fill]').forEach((b) => b.addEventListener('click', () => {
    const inp = $('targetInput');
    if (!inp.value.trim()) inp.value = b.dataset.fill;
    inp.placeholder = b.dataset.hint;
    inp.focus(); inp.setSelectionRange(inp.value.length, inp.value.length);
    onTargetInput();
  }));
  window.addEventListener('dragover', (e) => e.preventDefault());
  window.addEventListener('drop', (e) => e.preventDefault());
}

// --- Analyse ------------------------------------------------------------
// Schritte dieser Pruefung: Ohne Ordner oder Dateien laeuft keine KI, also auch keine KI-Schritte
const phasesForTargets = () => PHASES.filter((p) => needsAi() || !['analyze', 'validate'].includes(p.key));
function renderStepper(activeKey) {
  const phases = state.runPhases || PHASES;
  const ai = phases.findIndex((p) => p.key === activeKey);
  $('stepper').innerHTML = phases.map((p, i) => {
    const cls = i < ai ? 'past' : i === ai ? 'active' : '';
    return `<span class="pstep ${cls}">${esc(p.label)}</span>`;
  }).join('<span class="psep">›</span>');
}
