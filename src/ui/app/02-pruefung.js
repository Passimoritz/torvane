'use strict';

// Vigil-Oberfläche, Teil 2/9: Kosten-/Zeit-Vorschau, Prüflauf, Fortschritt, Ergebnisseite.
// Klassisches Skript – teilt den globalen Gueltigkeitsbereich mit den anderen Teilen in src/ui/app/.

// --- Kosten-/Token-Vorschau vor dem Start -----------------------------------
const fmtDur = (s) => (s < 90 ? `≈ ${Math.max(1, Math.round(s / 10) * 10)} Sek.` : s < 3600 ? `≈ ${Math.round(s / 60)} Min.` : `≈ ${(s / 3600).toFixed(1).replace('.', ',')} Std.`);
const fmtK = (n) => (n >= 1e6 ? (n / 1e6).toFixed(2).replace('.', ',') + ' Mio.' : n >= 1000 ? Math.round(n / 1000).toLocaleString(uiLocale()) + ' Tsd.' : String(n));
let estTimer = null;
let estSeq = 0;
function scheduleEstimate(show) {
  clearTimeout(estTimer);
  if (!show) { $('estimateCard').hidden = true; state.estimate = null; setRunEta(); return; }
  estTimer = setTimeout(refreshEstimate, 350);
}
// Dauer kommt komplett aus der Vorschau des Hauptprozesses (lernt aus echten Laeufen mit).
function expectedSeconds() {
  return state.targets.length && state.estimate ? state.estimate.seconds : null;
}
// Restzeit waehrend des Laufs: Plan minus verbrauchte Zeit, ab dem ersten KI-Aufruf
// hochgerechnet aus dem tatsaechlichen Tempo (die KI ist fast immer der groesste Teil).
function remainingSeconds(elapsedS) {
  const live = state.live || {};
  const est = state.estimate;
  if (live.aiDone > 0 && live.aiTotal) {
    const rate = (Date.now() - live.aiStart) / 1000 / live.aiDone;
    const left = live.aiTotal - live.aiDone;
    const validate = est && est.calls ? Math.ceil(live.aiTotal / 4) : 0;
    return rate * (left + (live.phase === 'validate' ? Math.max(0, (live.valTotal || validate) - (live.valDone || 0)) : validate));
  }
  const exp = expectedSeconds();
  return exp == null ? null : exp - elapsedS;
}
// Checkliste "Startklar?" neben dem Start-Button
function updateReady(ready) {
  const n = state.targets.length;
  const set = (id, ok, text) => { const li = $(id); li.classList.toggle('ok', ok); li.querySelector('.ready-text').textContent = text; };
  set('readyTarget', n > 0, n ? `${n} ${n === 1 ? 'Ziel' : 'Ziele'} in der Prüfliste` : 'Ziel hinzufügen');
  set('readyAi', ready.ok, !needsAi() ? (n ? 'Keine KI nötig für diese Ziele' : 'KI wird nur für Code gebraucht') : ready.ok ? `KI bereit: ${ready.label}` : (ready.why || 'KI wählen'));
  const s = expectedSeconds();
  const est = state.estimate;
  const costText = !n ? 'Kosten und Dauer prüfen'
    : !needsAi() ? `Kostenlos · ${s ? fmtDur(s) : 'kurz'}`
      : est ? `${est.local ? 'Kostenlos' : est.priced ? '≈ ' + fmtUsd(est.usd) : 'Preis unbekannt'} · ${fmtDur(s)}` : 'Schätzung wird berechnet …';
  set('readyCost', n > 0 && (!needsAi() || !!est), costText);
}
// Voraussichtliche Zeit direkt im Start-Button
function setRunEta() {
  const s = state.running ? null : expectedSeconds();
  $('runEta').hidden = s == null;
  if (s != null) $('runEta').textContent = fmtDur(s);
}
async function refreshEstimate() {
  const seq = ++estSeq;
  const card = $('estimateCard');
  // Ohne KI (nur Webadressen/Images) keine Karte, aber trotzdem die Dauer schaetzen
  const showCard = needsAi();
  card.hidden = !showCard;
  card.classList.add('loading');
  card.innerHTML = '<div class="est-head"><span>Vorschau dieses Laufs</span><span class="muted small">rechne …</span></div>';
  let r;
  try { r = await window.vigil.estimateAudit({ targets: state.targets, providerId: state.config.selected, ...(gbRunApplies() ? { useGreenbone: gbRunOn() } : {}) }); } catch (e) { r = { ok: false, error: e.message }; }
  if (seq !== estSeq) return; // inzwischen geaendert
  card.classList.remove('loading');
  if (!showCard) { state.estimate = r && r.ok ? r.current : null; setRunEta(); updateReady({ ok: true }); return; }
  if (!r || !r.ok) { card.innerHTML = `<div class="est-head"><span>Vorschau</span></div><p class="muted small">Keine Schätzung möglich${r && r.error ? ': ' + esc(r.error) : ''}.</p>`; return; }
  const c = r.current, o = r.other;
  state.estimate = c;
  setRunEta();
  updateReady(needsAi() ? aiReady() : { ok: true });
  const total = c.inputTokens + c.outputTokens;
  const price = c.local ? '<b class="est-price free">Kostenlos</b><span class="muted small">läuft lokal auf deinem Rechner</span>'
    : c.priced ? `<b class="est-price">≈ ${esc(fmtUsd(c.usd))}</b><span class="muted small">${esc(r.model || '')}</span>`
      : `<b class="est-price">${fmtK(total)} Tokens</b><span class="muted small">kein Preis für „${esc(r.model || '?')}“ hinterlegt</span>`;
  const modeName = (d) => (d === 'thorough' ? 'Gründlich' : 'Schnell');
  const otherPrice = o.local ? fmtDur(o.seconds) : o.priced ? `≈ ${fmtUsd(o.usd)} · ${fmtDur(o.seconds)}` : `${fmtK(o.inputTokens + o.outputTokens)} Tokens`;
  const warn = !c.local && c.priced && c.usd > (state.config.costWarnUsd ?? 2);
  card.innerHTML = `
    <div class="est-head"><span>Vorschau dieses Laufs</span><span class="est-mode">${modeName(c.depth)}</span></div>
    <div class="est-main">${price}</div>
    <div class="est-grid">
      <div><span class="est-n">${fmtK(total)}</span><span class="est-l">Tokens</span></div>
      <div><span class="est-n">${c.calls}</span><span class="est-l">KI-Aufrufe</span></div>
      <div><span class="est-n">${c.files}</span><span class="est-l">Dateien</span></div>
      <div><span class="est-n">${fmtDur(c.seconds).replace('≈ ', '')}</span><span class="est-l">Dauer</span></div>
    </div>
    <div class="est-split muted small">${fmtK(c.inputTokens)} Eingang · ${fmtK(c.outputTokens)} Ausgang${c.truncated ? ' · große Projekte werden gekürzt' : ''}</div>
    <div class="est-split muted small">${c.timeMeasured ? 'Dauer aus deinen bisherigen Läufen gelernt' : 'Dauer vorsichtig geschätzt – wird nach dem ersten Lauf mit diesem Modell genauer'}</div>
    ${warn ? `<div class="est-warn">Über deiner Kostengrenze von ${fmtUsd(state.config.costWarnUsd ?? 2)} – Vigil fragt vor dem Start nach.</div>` : ''}
    <button type="button" class="est-switch" id="estSwitch">${modeName(o.depth)}-Modus: ${esc(otherPrice)} – umstellen</button>`;
  $('estSwitch').onclick = () => { state.config.analysisDepth = o.depth; saveCfg(); refreshEstimate(); toast(`${modeName(o.depth)}-Modus aktiv`, 'ok'); };
}

// Protokoll: neueste Zeile oben. Wer oben steht, sieht sie sofort; wer nach unten gescrollt hat,
// bleibt an derselben Stelle stehen (die neue Zeile schiebt den Inhalt nicht weg).
function appendRunLog(line) {
  const log = $('log');
  const atTop = log.scrollTop < 24;
  const before = log.scrollHeight;
  const lines = String(line).replace(/\n+$/, '').split('\n').reverse().join('\n');
  log.textContent = lines + '\n' + log.textContent;
  if (!atTop) log.scrollTop += log.scrollHeight - before;
}

async function runAudit(opts = {}) {
  if (state.running || !state.targets.length) return;
  const resumeId = opts.resumeId || null;
  // Es gibt nur einen gespeicherten Stand: ein neuer Lauf ersetzt ihn
  if (!resumeId && state.pausedRun && !confirm('Es gibt noch eine pausierte Prüfung. Wenn du jetzt neu startest, wird ihr Stand verworfen.\n\nTrotzdem starten?')) return;
  // Kostenbremse: teure Cloud-Laeufe vorher bestaetigen lassen
  const est = state.estimate;
  if (!resumeId && needsAi() && est && !est.local && est.priced && est.usd > (state.config.costWarnUsd ?? 2)
    && !confirm(`Dieser Lauf kostet voraussichtlich ${fmtUsd(est.usd)} (${fmtK(est.inputTokens + est.outputTokens)} Tokens, ${est.calls} KI-Aufrufe).\n\nTrotzdem starten?`)) return;
  // Monatliches KI-Budget: erreicht oder durch diesen Lauf ueberschritten -> ausdruecklich bestaetigen
  let budgetConfirmed = false;
  const localRun = (est && est.local) || state.config.selected === 'ollama';
  if (!resumeId && needsAi() && !localRun && (state.config.monthlyBudgetUsd || 0) > 0 && window.vigil.budgetStats) {
    let b = null;
    try { b = await window.vigil.budgetStats(); } catch { /* ohne Budget-Info */ }
    const add = est && est.priced ? est.usd : 0;
    if (b && b.budget && (b.exceeded || b.spent + add > b.budget)) {
      if (!confirm(`Monatliches KI-Budget: ${fmtUsd(b.spent)} von ${fmtUsd(b.budget)} ausgegeben.\n${add ? `Dieser Lauf kostet voraussichtlich weitere ${fmtUsd(add)}.\n` : ''}\nTrotzdem starten?`)) return;
      budgetConfirmed = true;
    }
  }
  state.pausedRun = null; if (typeof renderPausedRun === 'function') renderPausedRun();
  state.runStartedAt = Date.now();
  state.running = true; updateRunState();
  $('cancelBtn').hidden = false; $('cancelBtn').disabled = false;
  setPaused(false); $('pauseBtn').hidden = false; $('pauseBtn').disabled = false;
  $('progressPanel').hidden = false;
  $('emptyState').hidden = true;
  $('resultPanel').hidden = true;
  $('resultActions').hidden = true;
  $('log').textContent = '';
  $('costPanel').hidden = true; $('costPanel').innerHTML = '';
  $('barFill').style.width = '0%';
  $('progressTitle').textContent = 'Prüfung läuft …';
  $('progressPanel').classList.remove('done', 'failed');
  state.runPhases = phasesForTargets();
  renderStepper('ingest');
  resetStage();
  $('baselineStatus').textContent = 'Prüfung läuft – die Befunde erscheinen hier, sobald sie fertig ist.';
  showView('results');
  renderFlow();
  // Laufzeit und Restzeit live mitzaehlen
  const expected = expectedSeconds();
  const tick = () => {
    const ms = Date.now() - state.runStartedAt;
    $('progressSub').textContent = `${state.targets.map((t) => t.value).join(', ')} · ${fmtElapsed(ms)}`;
    $('stageElapsed').textContent = fmtElapsed(ms);
    const left = remainingSeconds(ms / 1000);
    if (left == null) $('stageEta').textContent = '–';
    else $('stageEta').textContent = left > 5 ? fmtDur(left).replace('≈ ', '') : expected != null && ms / 1000 > expected * 1.15 ? 'dauert länger als geplant' : 'gleich';
  };
  tick();
  clearInterval(state.elapsedTimer);
  state.elapsedTimer = setInterval(tick, 1000);

  state.live = {};
  const unsub = window.vigil.onProgress((p) => {
    const live = state.live;
    live.phase = p.phase;
    if (p.phase === 'analyze' && p.total) { if (!live.aiStart) live.aiStart = Date.now(); live.aiTotal = p.total; live.aiDone = p.done || 0; }
    if (p.phase === 'validate' && p.total) { live.valTotal = p.total; live.valDone = p.done || 0; }
    renderStepper(p.phase);
    updateStage(p);
    appendRunLog(`[${p.phase}]${p.total ? ` ${p.done}/${p.total}` : ''} ${p.message}\n`);
    if (p.total) $('barFill').style.width = Math.round((p.done / p.total) * 100) + '%';
    if (p.cost) updateCost(p.cost, false);
  });

  const res = await window.vigil.runAudit({ targets: state.targets, providerId: opts.providerId || state.config.selected, ...(budgetConfirmed ? { budgetConfirmed: true } : {}), ...(resumeId ? { resumeId } : {}), ...(!resumeId && gbRunApplies() ? { useGreenbone: gbRunOn() } : {}) });
  // Bestaetigte Hosts hat der Main-Prozess auf die Freigabeliste gesetzt.
  try { state.config.allowlist = (await window.vigil.getConfig()).allowlist || []; } catch { /* egal */ }
  loadKnown();
  unsub();
  clearInterval(state.elapsedTimer);
  closeTimeline();
  state.gbChoice = null; // Die Wahl gilt nur fuer diese eine Pruefung
  state.running = false; updateRunState(); setRunEta();
  $('cancelBtn').hidden = true;
  $('pauseBtn').hidden = true; setPaused(false);
  const took = fmtElapsed(Date.now() - state.runStartedAt);

  if (!res.ok) {
    $('progressTitle').textContent = 'Prüfung fehlgeschlagen';
    $('progressSub').textContent = res.error;
    $('progressPanel').classList.add('failed');
    renderStepper('');
    showTech(true, 'raw');
    appendRunLog('FEHLER: ' + res.error + '\n');
    toast('Prüfung fehlgeschlagen: ' + res.error, 'err');
    return;
  }
  $('barFill').style.width = '100%';
  $('progressTitle').textContent = res.canceled ? 'Abgebrochen – Teilergebnis' : 'Prüfung abgeschlossen';
  $('progressSub').textContent = `${state.targets.map((t) => t.value).join(', ')} · Dauer ${took}`;
  $('progressPanel').classList.add('done');
  renderStepper(res.canceled ? '' : 'done');
  if (res.result) {
    if (res.result.meta && res.result.meta.usage) updateCost(res.result.meta.usage, true);
    renderResult(res.result);
    const n = (res.result.findings || []).filter((f) => !f.suppressed).length;
    toast(res.canceled ? 'Abgebrochen – Teilergebnis geladen' : `Fertig: ${n} ${n === 1 ? 'Befund' : 'Befunde'} in ${took}`, 'ok');
  }
}
// --- Buehne und Zwischenschritte ------------------------------------------------------
// Jeder Schritt hat eine Szene; innerhalb des Schritts waehlt die laufende Meldung einen Zwischenschritt
// mit eigener Szene (Werkzeug, Server-Check, KI-Block …). Erste passende Regel gewinnt, die Meldungen
// kommen deutsch aus dem Kern. Ohne eigene Szene bleibt die des Schritts. Entwurf: Design-Leinwand.
const SUBSTEPS = [
  ['ingest', /Entpacke/, 'unpack', 'Archive werden entpackt'],
  ['ingest', null, 'ingest', 'Dateien werden gelesen'],
  ['prescan', /Git-Historie/, 'git', 'Alte Git-Versionen werden durchsucht'],
  ['prescan', /Schadsoftware|Defender|YARA/, 'malware', 'Suche nach Schadsoftware'],
  ['prescan', /Texterkennung/, 'ocr', 'Text in Bildern wird gelesen'],
  ['prescan', null, 'prescan', 'Code wird nach bekannten Mustern durchsucht'],
  ['cve', /Details/, 'cvedetails', 'Details zu den Lücken werden geholt'],
  ['cve', null, 'cve', 'Pakete werden mit der Lücken-Datenbank abgeglichen'],
  ['webscan', /TLS|Zertifikat/, 'tls', 'Zertifikat und Verschlüsselung werden geprüft'],
  ['webscan', /Unterseiten|Formulare/, 'crawl', 'Unterseiten und Formulare werden durchgegangen'],
  ['webscan', /Login/, 'login', 'Anmeldung mit dem Testkonto wird geprüft'],
  ['webscan', /Browser|API-Rechtematrix/, 'browser', 'Seite wird im Browser geprüft'],
  ['webscan', null, 'webscan', 'Server und offene Pfade werden geprüft'],
  ['active', /gitleaks|trufflehog/, 'secrets', 'Suche nach Zugangsdaten'],
  ['active', /semgrep|bandit|checkov|hadolint/, 'sast', 'Code wird mit Regeln geprüft'],
  ['active', /osv-scanner|grype|retire/, 'deps', 'Abhängigkeiten werden geprüft'],
  ['active', /trivy/, 'container', 'Container wird Schicht für Schicht geprüft'],
  ['active', /Greenbone/, 'greenbone', 'Greenbone prüft den Server'],
  ['active', null, 'active', 'Dienste im Netz werden geprüft'],
  ['analyze', /Ordne|Vorsortierung/, 'sort', 'Dateien werden nach Risiko sortiert'],
  ['analyze', null, 'analyze', 'Die KI liest den Code'],
  ['validate', null, 'validate', 'Funde werden gegengeprüft'],
  ['done', null, 'done', 'Fertig'],
];
const TOOL_RE = /^(gitleaks|trufflehog|trivy|grype|semgrep|bandit|checkov|retire\.js|hadolint|osv-scanner|nmap|nuclei|YARA)\b/i;
function classifySub(p) {
  const msg = String(p.message || '');
  const hit = SUBSTEPS.find(([ph, re]) => ph === p.phase && (!re || re.test(msg))) || [p.phase, null, p.phase, msg];
  const gb = p.gb ? SUBSTEPS.find((s) => s[2] === 'greenbone') : null;
  const [, , key, label] = gb || hit;
  const tool = (msg.match(TOOL_RE) || [])[1] || (gb ? 'Greenbone' : '');
  return { phase: p.phase, key, label, tool };
}
function setStageScene(key, pct) {
  const v = $('stageVisual');
  if (!v) return;
  if (key) {
    const want = v.querySelector(`.scene[data-scene="${key}"]`) ? key : null;
    if (want) v.querySelectorAll('.scene').forEach((g) => g.classList.toggle('on', g.dataset.scene === want));
  }
  if (pct != null) $('stageRing').style.strokeDashoffset = String(100 - Math.max(0, Math.min(100, pct)));
}
function resetStage() {
  state.stagePhase = null;
  state.timeline = [];
  setStageScene('ingest', 0);
  $('stagePhase').textContent = state.runPhases[0].label;
  $('stageStep').textContent = `Schritt 1 von ${state.runPhases.length}`;
  $('stageMsg').textContent = 'Starte …';
  $('stagePct').textContent = '0 %';
  $('stageSubLabel').textContent = SUBSTEPS[1][3];
  $('stageSubTool').hidden = true;
  $('stageTrail').innerHTML = '';
  renderTimeline();
}
function updateStage(p) {
  const phases = state.runPhases;
  const i = phases.findIndex((x) => x.key === p.phase);
  if (i >= 0 && p.phase !== state.stagePhase) {
    state.stagePhase = p.phase;
    const el = $('stagePhase');
    el.textContent = phases[i].label;
    el.classList.remove('swap'); void el.offsetWidth; el.classList.add('swap');
    $('stageStep').textContent = `Schritt ${i + 1} von ${phases.length}`;
    setStageScene(null, p.phase === 'done' ? 100 : 0);
  }
  if (p.message) $('stageMsg').textContent = p.message;
  const pct = p.total ? Math.round((p.done / p.total) * 100) : null;
  $('stagePct').textContent = pct != null ? pct + ' %' : '–';
  const sub = trackSub(p);
  setStageScene(sub.key, pct);
  $('stageSubLabel').textContent = sub.label;
  $('stageSubTool').hidden = !sub.tool;
  $('stageSubTool').textContent = sub.tool;
  // Die letzten erledigten Zwischenschritte als kleine Haken-Pillen
  const doneSubs = state.timeline.filter((e) => e.end).slice(-3);
  $('stageTrail').innerHTML = doneSubs.map((e) => `<li>${esc(e.tool || e.label)}</li>`).join('');
}

// Zeitleiste fuer "Technische Details": aufeinanderfolgende Meldungen desselben Zwischenschritts
// (gleiche Szene, gleiches Werkzeug) bilden eine Zeile, deren Fortschritt mitlaeuft.
function trackSub(p, now = Date.now()) {
  const sub = classifySub(p);
  const tl = state.timeline || (state.timeline = []);
  const last = tl[tl.length - 1];
  if (last && !last.end && last.key === sub.key && last.tool === sub.tool && last.phase === sub.phase) {
    last.detail = p.message || last.detail; last.count++;
    if (p.total) { last.done = p.done; last.total = p.total; }
  } else {
    if (last && !last.end) last.end = now;
    tl.push({ ...sub, detail: p.message || '', start: now, end: p.phase === 'done' ? now : null, count: 1, done: p.total ? p.done : null, total: p.total || null });
  }
  scheduleTimeline();
  return sub;
}
function closeTimeline(now = Date.now()) {
  for (const e of state.timeline || []) if (!e.end) e.end = now;
  renderTimeline();
}
let tlFrame = 0;
function scheduleTimeline() { if (!tlFrame) tlFrame = requestAnimationFrame(() => { tlFrame = 0; renderTimeline(); }); }
const fmtClock = (ms) => { const s = Math.max(0, Math.round(ms / 1000)); return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, '0')}`; };
function renderTimeline() {
  const box = $('timeline');
  if (!box) return;
  const tl = state.timeline || [];
  const t0 = state.runStartedAt || (tl[0] && tl[0].start) || Date.now();
  const labelOf = (ph) => (PHASES.find((x) => x.key === ph) || { label: ph }).label;
  // Neueste oben: Schritte und Zeilen in umgekehrter Reihenfolge
  let html = '', phase = null;
  for (const e of tl.slice().reverse()) {
    if (e.phase !== phase) { phase = e.phase; html += `<li class="tl-phase">${esc(labelOf(phase))}</li>`; }
    const pct = e.total ? Math.round((e.done / e.total) * 100) : null;
    const side = pct != null ? `<span class="tl-bar"><i style="width:${pct}%"></i></span><span class="tl-count">${e.done}/${e.total}</span>`
      : e.end ? `<span class="tl-dur">${esc(fmtElapsed(e.end - e.start))}</span>` : '';
    html += `<li class="tl-row ${e.end ? 'done' : 'now'}"><span class="tl-time">${fmtClock(e.start - t0)}</span><span class="tl-state" aria-hidden="true">${e.end ? '✓' : ''}</span><span class="tl-main"><span class="tl-label">${esc(e.label)}</span><span class="tl-detail" data-no-i18n title="${esc(e.detail)}">${esc(e.detail)}</span></span><span class="tl-side">${side}</span></li>`;
  }
  const atTop = box.scrollTop < 24, before = box.scrollHeight;
  box.innerHTML = html || '<li class="tl-phase">Noch keine Schritte</li>';
  if (!atTop) box.scrollTop += box.scrollHeight - before;
  const steps = tl.filter((e) => e.end).length;
  const msgs = tl.reduce((n, e) => n + e.count, 0);
  $('techStats').innerHTML = `<span><b>${steps}</b> ${steps === 1 ? 'Zwischenschritt' : 'Zwischenschritte'} erledigt</span><span><b>${msgs}</b> Meldungen</span>`;
}
// Ansicht der technischen Details: Ablauf (Zeitleiste) oder Rohprotokoll
function setTechView(v) {
  const raw = v === 'raw';
  $('timeline').hidden = raw; $('log').hidden = !raw;
  $('techSeg').querySelectorAll('button').forEach((b) => b.setAttribute('aria-checked', String(b.dataset.tech === v)));
}
function showTech(open, view) {
  $('tech').hidden = !open;
  if (view) setTechView(view);
}
const fmtElapsed = (ms) => { const s = Math.round(ms / 1000); return s < 60 ? `${s} s` : `${Math.floor(s / 60)}:${String(s % 60).padStart(2, '0')} min`; };

// Live-Anzeige von Token-/$-Verbrauch. Nur bei nicht-lokalen Anbietern sichtbar.
function fmtUsd(u) {
  if (u >= 0.1) return '$' + u.toFixed(2);
  if (u >= 0.005) return '$' + u.toFixed(3);
  if (u > 0) return '< $0,005';
  return '$0,00';
}
function fmtTok(n) { return Number(n || 0).toLocaleString(uiLocale()); }
function updateCost(cost, done) {
  const el = $('costPanel');
  if (!cost || cost.local) { el.hidden = true; return; } // lokal = kostenlos, nichts anzeigen
  el.hidden = false;
  const inT = fmtTok(cost.inputTokens), outT = fmtTok(cost.outputTokens);
  const totalT = fmtTok((cost.inputTokens || 0) + (cost.outputTokens || 0));
  const label = cost.estimate ? 'Geschätzt' : (done ? 'Kosten gesamt' : 'Bisher');
  const usd = cost.priced ? `≈ ${esc(fmtUsd(cost.usd || 0))}` : `${esc(totalT)} Tokens`;
  const was = done && state.estimate && state.estimate.priced && !cost.estimate ? ` · Vorschau ≈ ${esc(fmtUsd(state.estimate.usd))}` : '';
  el.title = `${totalT} Tokens · ${inT} Eingang · ${outT} Ausgang${cost.priced ? '' : ' · Modell nicht in der Preisliste'}`;
  el.innerHTML = `<span class="cost-label">${esc(label)}</span><span class="cost-usd">${usd}</span>` +
    `<span class="cost-tok">${cost.priced ? esc(totalT) + ' Tokens' : 'kein Preis hinterlegt'}${was}</span>`;
}

// Sicherheitsnote A–F aus den (nicht ausgeblendeten) Befunden.
const SEV_WEIGHT = { critical: 30, high: 14, medium: 5, low: 1.5, info: 0 };
function riskScore(counts) {
  const penalty = SEV_ORDER.reduce((sum, s) => sum + (counts[s] || 0) * SEV_WEIGHT[s], 0);
  const score = Math.max(0, Math.round(100 - penalty));
  const grade = score >= 92 ? 'A' : score >= 78 ? 'B' : score >= 60 ? 'C' : score >= 40 ? 'D' : score >= 20 ? 'E' : 'F';
  return { score, grade };
}
function visibleCounts() {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  state.lastFindings.forEach((f) => { if (!f.suppressed) counts[f.severity]++; });
  return counts;
}
const plural = (n, one, many) => (n === 1 ? one : many);

function renderVerdict() {
  const c = visibleCounts();
  const total = SEV_ORDER.reduce((n, s) => n + c[s], 0);
  let kind = 'ok', head = 'Keine Probleme gefunden.', sub = 'Vigil hat nichts Auffälliges entdeckt – gute Arbeit.';
  if (total > 0) {
    sub = 'Fang oben in der Liste an – dort steht das Dringendste. Eine Stufe anklicken filtert die Liste.';
    if (c.critical) { kind = 'crit'; head = `${c.critical} kritische${c.high ? ` und ${c.high} hohe` : ''} ${plural(c.critical + c.high, 'Lücke', 'Lücken')} – bitte zuerst beheben.`; }
    else if (c.high) { kind = 'high'; head = `${c.high} ${plural(c.high, 'Problem', 'Probleme')} mit hohem Risiko gefunden.`; }
    else if (c.medium) { kind = 'med'; head = `${c.medium} ${plural(c.medium, 'Problem', 'Probleme')} mittleren Risikos gefunden.`; }
    else { kind = 'low'; head = `Nur ${total} ${plural(total, 'kleiner Hinweis', 'kleinere Hinweise')} – insgesamt solide.`; }
  }
  const { score, grade } = riskScore(c);
  const stats = SEV_ORDER.map((s) => `<button type="button" class="stat c-${SEV_CLS[s]}${state.filter === s ? ' active' : ''}" data-f="${s}" title="${esc(SEV_HELP[s])}"${c[s] ? '' : ' disabled'}>
      <span class="stat-n">${c[s]}</span><span class="stat-l">${SEV_LABEL[s]}</span></button>`).join('');
  const merged = state.lastFindings.reduce((n, f) => n + Math.max(0, (f.mergedCount || 1) - 1), 0);
  const meta = (state.lastResult && state.lastResult.meta) || {};
  const notes = [];
  if (merged) notes.push(`${merged} doppelte ${plural(merged, 'Meldung', 'Meldungen')} aus verschiedenen Prüfungen zusammengeführt.`);
  if (meta.refuted) notes.push(`${meta.refuted} KI-${plural(meta.refuted, 'Befund', 'Befunde')} bei der Gegenprüfung widerlegt und verworfen.`);
  if (meta.redacted) notes.push(`${meta.redacted} ${plural(meta.redacted, 'Secret', 'Secrets')} vor dem Versand an die KI geschwärzt.`);
  const unverified = state.lastFindings.filter((f) => !f.suppressed && f.assurance === 'unverified').length;
  const noteHtml = notes.map((n) => `<span class="merge-note">${esc(n)}</span>`).join('') +
    (unverified ? `<span class="merge-note warn">${unverified} ${plural(unverified, 'Befund ist', 'Befunde sind')} nur von der KI gemeldet und unbestätigt – bitte selbst prüfen.</span>` : '');
  const mergeNote = noteHtml ? `<div class="merge-notes">${noteHtml}</div>` : '';

  const v = $('verdict');
  v.className = 'verdict card v-' + kind;
  v.innerHTML = `
    <div class="score" style="--p:${score}" role="img" aria-label="Sicherheitsnote ${grade}, ${score} von 100">
      <div class="score-inner"><span class="score-grade">${grade}</span><span class="score-label">${score} / 100</span></div>
    </div>
    <div class="v-main">
      <span class="v-eyebrow">Fazit</span>
      <h2 class="v-head">${esc(head)}</h2>
      <p class="v-sub">${esc(sub)}</p>
    </div>
    <div class="stats" role="group" aria-label="Nach Schwere filtern">${stats}</div>
    ${mergeNote}`;
  v.querySelectorAll('.stat').forEach((b) => b.onclick = () => setFilter(state.filter === b.dataset.f ? 'all' : b.dataset.f));
}

function setFilter(f) {
  state.filter = f;
  renderVerdict(); renderFilters(); renderFindings();
}
function renderFilters() {
  const c = visibleCounts();
  const total = SEV_ORDER.reduce((n, s) => n + c[s], 0);
  const btn = (f, label, n, dot) => `<button class="fbtn${state.filter === f ? ' active' : ''}" data-f="${f}" role="tab" aria-selected="${state.filter === f}">${dot ? `<span class="fdot c-${dot}"></span>` : ''}${label}<span class="fcount">${n}</span></button>`;
  const box = $('filters');
  box.innerHTML = btn('all', 'Alle', total) + SEV_ORDER.filter((s) => c[s]).map((s) => btn(s, SEV_LABEL[s], c[s], SEV_CLS[s])).join('');
  box.querySelectorAll('.fbtn').forEach((b) => b.onclick = () => setFilter(b.dataset.f));
}

// Befundtexte kommen deutsch aus den Pruefmodulen; in der englischen Oberflaeche uebersetzen
const wantEnglish = () => state.config && state.config.lang !== 'de' && !!window.VigilFindingsI18n;
function renderResult(result) {
  state.rawResult = result;
  if (wantEnglish()) result = window.VigilFindingsI18n.localizeResult(result);
  state.lastFindings = result.findings || [];
  state.lastResult = result;
  state.filter = 'all'; state.query = ''; state.onlyNew = false; state.onlyProven = false; state.showSuppressed = false;
  state.selected = null;
  $('findingSearch').value = '';
  $('resultPanel').hidden = false;
  $('resultActions').hidden = false;
  $('emptyState').hidden = true;
  const open = state.lastFindings.filter((f) => !f.suppressed);
  const badge = $('navResultsCount');
  badge.hidden = !open.length;
  badge.textContent = open.length;
  badge.classList.toggle('alarm', open.some((f) => f.severity === 'critical' || f.severity === 'high'));

  if (result.errors && result.errors.length) {
    showTech(true, 'raw');
    appendRunLog('Hinweise:\n' + result.errors.map((e) => '  - ' + e).join('\n') + '\n');
  }
  refreshResultView();
}
function refreshResultView() {
  renderVerdict(); renderRunSummary(); renderThreatModel(); renderFilters(); updateBaselineStatus(); renderViewToggles(); renderFindings(); renderFlow();
}

// Zusammenfassung des Laufs (KI oder regelbasiert, aus result.meta.runSummary)
function renderRunSummary() {
  const el = $('runSummary'); if (!el) return;
  const s = state.lastResult && state.lastResult.meta && state.lastResult.meta.runSummary;
  el.hidden = !(s && s.text);
  if (!s || !s.text) return;
  el.innerHTML = `<details><summary><span class="rs-label">Zusammenfassung</span><span class="rs-text">${esc(s.text)}</span></summary><p>${esc(s.text)}</p><span class="muted small">${s.source === 'ai' ? `von der KI geschrieben${s.model ? ' (' + esc(s.model) + ')' : ''}` : 'regelbasiert erstellt'}</span></details>`;
}
