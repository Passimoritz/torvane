#!/usr/bin/env node
'use strict';

// Kleine CLI zum Testen des Kerns ohne GUI.
// Beispiel:
//   node src/cli.js --provider ollama --model qwen2.5-coder ./mein-ordner ./app.jar
//   node src/cli.js --provider anthropic --model claude-sonnet-4-5 --out report.html ./src
//   node src/cli.js --format gitlab --out gl-sast-report.json ./src   (auch: junit, checkstyle, csv, sarif, md, json, html)

require('dotenv').config();
const fs = require('fs');
const path = require('path');
const { runAudit, report, atOrAbove } = require('./core');

function parseArgs(argv) {
  const opts = { targets: [], provider: 'ollama', model: '', out: '', baseUrl: '', authorize: false, cveLookup: true, deep: false, validate: true, redact: true, failOn: '', format: '', lang: 'en' };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--provider') opts.provider = argv[++i];
    else if (a === '--model') opts.model = argv[++i];
    else if (a === '--base-url') opts.baseUrl = argv[++i];
    else if (a === '--out') opts.out = argv[++i];
    else if (a === '--url') opts.targets.push({ type: 'url', value: argv[++i], authorized: true }); // explizit auf der Kommandozeile = freigegeben
    else if (a === '--image') opts.targets.push({ type: 'image', value: argv[++i] });
    else if (a === '--endpoint') opts.targets.push({ type: 'endpoint', value: argv[++i], authorized: true });
    else if (a === '--authorize') opts.authorize = true;
    else if (a === '--no-cve') opts.cveLookup = false;
    else if (a === '--deep') opts.deep = true;
    else if (a === '--no-validate') opts.validate = false;
    else if (a === '--no-redact') opts.redact = false;
    else if (a === '--fail-on') opts.failOn = argv[++i];
    else if (a === '--format') opts.format = argv[++i];
    else if (a === '--lang') opts.lang = argv[++i] === 'de' ? 'de' : 'en';
    else if (a === '--sbom') opts.sbom = argv[++i];
    else if (a === '--sbom-format') opts.sbomFormat = argv[++i] === 'spdx' ? 'spdx' : 'cyclonedx';
    else if (a === '--live-secrets') opts.secretLive = true;
    else if (a === '--rules-only') opts.rulesOnly = true;
    else if (a === '--staged') { opts.staged = true; opts.rulesOnly = true; }
    else if (a === '--watch') { opts.watch = true; opts.rulesOnly = true; }
    else if (a === '--install-hook') opts.installHook = true;
    else if (a === '--issues') opts.issues = argv[++i];
    else if (a === '--dry-run') opts.dryRun = true;
    else if (a === '--min-severity') opts.minSeverity = argv[++i];
    else if (a === '--pr-review') opts.prReview = true;
    else if (a === '--fail-on-tests') opts.failOnTests = true;
    else if (a === '--keygen') opts.keygen = argv[++i];
    else if (a === '--sign-rules') opts.signRules = argv[++i];
    else if (a === '--key') opts.key = argv[++i];
    else if (a === '--trust-key') opts.trustKey = argv[++i];
    else if (a === '--install-rules') opts.installRules = argv[++i];
    else opts.targets.push({ type: 'path', value: path.resolve(a) });
  }
  return opts;
}

// Ausgabeformate fuer --format (CI: GitLab SAST, JUnit, Checkstyle)
const FORMATS = ['html', 'md', 'json', 'sarif', 'gitlab', 'junit', 'checkstyle', 'csv'];

function keyFor(provider) {
  return {
    anthropic: process.env.ANTHROPIC_API_KEY,
    openai: process.env.OPENAI_API_KEY,
    gemini: process.env.GEMINI_API_KEY,
    compat: process.env.OPENAI_COMPAT_API_KEY,
  }[provider] || '';
}

(async () => {
  const o = parseArgs(process.argv.slice(2));
  const flow = require('./core/devflow');
  if (o.format && !FORMATS.includes(o.format)) { console.error(`Unbekanntes Format: ${o.format} (erlaubt: ${FORMATS.join(', ')})`); process.exit(1); }
  // Regelpakete: Schluessel erzeugen, Paket signieren, Schluessel vertrauen, Paket installieren
  if (o.keygen || o.signRules || o.trustKey || o.installRules) {
    const rp = require('./core/rulepacks');
    try {
      if (o.keygen) {
        const k = rp.generateKeyPair();
        fs.mkdirSync(o.keygen, { recursive: true });
        fs.writeFileSync(path.join(o.keygen, 'rulepack-private.pem'), k.privateKeyPem, { mode: 0o600 });
        fs.writeFileSync(path.join(o.keygen, 'rulepack-public.pem'), k.publicKeyPem);
        console.log(`Schlüssel erzeugt in ${o.keygen} (privaten Teil sicher aufbewahren, öffentlichen weitergeben).`);
      }
      if (o.signRules) {
        if (!o.key) throw new Error('--key <privater-schluessel.pem> fehlt.');
        const priv = fs.readFileSync(o.key, 'utf8');
        const pub = require('crypto').createPublicKey(priv).export({ type: 'spki', format: 'pem' });
        const signed = rp.signPack(JSON.parse(fs.readFileSync(o.signRules, 'utf8')), priv, pub);
        fs.writeFileSync(o.signRules, JSON.stringify(signed, null, 2));
        console.log(`Regelpaket signiert: ${o.signRules} (Schlüssel ${signed.signature.keyId}).`);
      }
      if (o.trustKey) { const t = rp.trustKey(o.trustKey); console.log(`Schlüssel ${t.keyId} ist jetzt vertrauenswürdig.`); }
      if (o.installRules) {
        const r = await rp.installPack(o.installRules);
        if (!r.ok) throw new Error(r.error);
        console.log(`Regelpaket ${r.name} ${r.version || ''} installiert (${r.rules} Regeln): ${r.file}`);
      }
      process.exit(0);
    } catch (e) { console.error(`Regelpaket: ${e.message}`); process.exit(1); }
  }
  // --install-hook: pre-commit-Hook im aktuellen Repository einrichten
  if (o.installHook) {
    const r = flow.installHook(process.cwd(), { failOn: o.failOn || 'high' });
    console.log(r.ok ? `pre-commit-Hook eingerichtet: ${r.file}` : r.error);
    process.exit(r.ok ? 0 : 1);
  }
  // --staged: nur die gestagten Dateien pruefen (pre-commit), Standard-Schwelle "high"
  let staged = null;
  if (o.staged) {
    staged = flow.stagedSnapshot(process.cwd());
    if (!staged.files.length) { console.log('Keine gestagten Dateien.'); process.exit(0); }
    o.targets = [{ type: 'path', value: staged.snapshot }];
    if (!o.failOn) o.failOn = 'high';
    o.cveLookup = false;
  }
  if (!o.targets.length) {
    console.error('Nutzung: node src/cli.js [--provider ollama|anthropic|openai|gemini|compat] [--model …] [--out report.html] [--format html|md|json|sarif|gitlab|junit|checkstyle|csv] [--sbom sbom.cdx.json|sbom.spdx.json] [--live-secrets] <pfad|--url URL|--endpoint HOST> …');
    process.exit(1);
  }
  const config = {
    provider: o.provider,
    model: o.model,
    apiKey: keyFor(o.provider),
    baseUrl: o.baseUrl || (o.provider === 'compat' ? process.env.OPENAI_COMPAT_BASE_URL : o.provider === 'ollama' ? process.env.OLLAMA_BASE_URL : ''),
    temperature: 0.1,
    maxTokens: 4096,
    cveLookup: o.cveLookup,
    analysisDepth: o.deep ? 'thorough' : 'standard',
    aiValidation: o.validate,
    redactSecrets: o.redact,
    lang: o.lang,
    secretLiveCheck: !!o.secretLive,
    rulesOnly: !!o.rulesOnly,
  };

  // --watch: beim Speichern erneut pruefen (nur Regeln) und nur Neues bzw. Behobenes melden
  if (o.watch) {
    const t = o.targets.find((x) => x.type === 'path');
    if (!t) { console.error('--watch braucht einen Ordner.'); process.exit(1); }
    console.log(`Beobachte ${t.value} – Strg+C beendet.`);
    // Zwischenspeicher im Speicher: nach dem ersten Lauf werden nur geaenderte Dateien neu geprueft
    const mem = new Map();
    config.ruleCache = { get: (k) => mem.get(k), set: (k, v) => { mem.set(k, v); } };
    flow.watchFolder(t.value, {
      run: async () => (await runAudit([t], { ...config, cveLookup: false }, () => {})).result.findings.filter((f) => !f.suppressed),
      onChange: ({ added, resolved, total, initial }) => {
        const time = new Date().toLocaleTimeString();
        if (initial) { console.log(`[${time}] ${total} Befund(e) im Ausgangsstand.`); return; }
        for (const f of added) console.log(`[${time}] NEU     [${f.severity}] ${f.title}  (${f.location})`);
        for (const f of resolved) console.log(`[${time}] BEHOBEN [${f.severity}] ${f.title}  (${f.location})`);
      },
    });
    return;
  }

  const { result } = await runAudit(o.targets, config, (p) => {
    const d = p.total ? ` [${p.done}/${p.total}]` : '';
    console.log(`· ${p.phase}${d}: ${p.message}`);
  });

  console.log(`\nBefunde: ${result.summary.total}  (crit ${result.summary.counts.critical}, high ${result.summary.counts.high}, med ${result.summary.counts.medium}, low ${result.summary.counts.low}, info ${result.summary.counts.info})`);
  for (const f of result.findings.slice(0, 50)) {
    console.log(`  [${f.severity}] ${f.title}  ${f.location ? '(' + f.location + ')' : ''}`);
  }
  if (result.errors?.length) console.log('\nHinweise:\n  ' + result.errors.join('\n  '));
  if (staged) { try { fs.rmSync(staged.dir, { recursive: true, force: true }); } catch { /* egal */ } }

  // --issues owner/repo: Befunde (Standard ab "high") als GitHub-Issues anlegen, ohne Doppelte; --dry-run zeigt nur an
  if (o.issues) {
    const payloads = flow.issuePayloads(result.findings, { minSeverity: o.minSeverity || 'high' });
    const r = await flow.createIssues(o.issues, payloads, { dryRun: !!o.dryRun });
    console.log(`\nIssues: ${r.planned.length} neu${o.dryRun ? ' (nur Vorschau)' : ''}, ${r.skipped} schon vorhanden.`);
    for (const p of r.planned) console.log(`  ${p.title}`);
    for (const u of r.created) if (u) console.log(`  angelegt: ${u}`);
  }

  // --pr-review: in GitHub Actions Kommentare an den geaenderten Zeilen des Pull Requests setzen
  if (o.prReview) {
    const ev = process.env.GITHUB_EVENT_PATH ? JSON.parse(fs.readFileSync(process.env.GITHUB_EVENT_PATH, 'utf8')) : null;
    const prq = ev && ev.pull_request;
    const t = o.targets.find((x) => x.type === 'path');
    if (!prq || !process.env.GITHUB_REPOSITORY || !t) console.log('\n--pr-review: kein Pull-Request-Ereignis gefunden, übersprungen.');
    else {
      const diff = require('child_process').execFileSync('git', ['diff', '-U0', `${prq.base.sha}...${prq.head.sha}`], { cwd: t.value, maxBuffer: 256 * 1024 * 1024 }).toString();
      const comments = flow.reviewComments(result.findings, flow.changedLines(diff), { rootName: path.basename(t.value), minSeverity: o.minSeverity || 'medium' });
      const r = await flow.postReview({ repo: process.env.GITHUB_REPOSITORY, pr: prq.number, commitId: prq.head.sha, comments });
      console.log(`\nPull Request: ${r.posted} Kommentar(e) an geänderten Zeilen gesetzt.`);
    }
  }

  if (o.out) {
    const fmt = o.format
      || (o.out.endsWith('.md') ? 'md' : o.out.endsWith('.sarif') ? 'sarif' : o.out.endsWith('.json') ? 'json' : o.out.endsWith('.csv') ? 'csv' : /junit.*\.xml$/i.test(o.out) ? 'junit' : /checkstyle.*\.xml$/i.test(o.out) ? 'checkstyle' : 'html');
    // Standard Englisch: Befundtexte und Berichtsvorlage uebersetzen (--lang de fuer Deutsch)
    const en = o.lang !== 'de';
    const res = en ? require('./core/findings-i18n').localizeResult(result) : result;
    const R = require('./core/report-en');
    const X = require('./core/exports');
    const ver = require('../package.json').version;
    const out = fmt === 'gitlab' ? X.toGitlabSast(res, ver) : fmt === 'junit' ? X.toJunit(res) : fmt === 'checkstyle' ? X.toCheckstyle(res) : fmt === 'csv' ? X.toCsv(res, { lang: o.lang })
      : fmt === 'md' ? (en ? R.localizeReportMd(report.toMarkdown(res)) : report.toMarkdown(res))
      : fmt === 'sarif' ? report.toSarif(res)
        : fmt === 'json' ? JSON.stringify(res, null, 2)
          : en ? R.localizeReportHtml(report.toHtml(res)) : report.toHtml(res);
    fs.writeFileSync(o.out, out, 'utf8');
    console.log(`\nReport (${fmt}) geschrieben: ${o.out}`);
  }

  // --sbom <datei>: Paketliste als CycloneDX 1.5 (Standard) bzw. SPDX 2.3 (--sbom-format spdx oder *.spdx.json)
  if (o.sbom) {
    const format = o.sbomFormat || (/\.spdx(\.json)?$/i.test(o.sbom) ? 'spdx' : 'cyclonedx');
    const name = (o.targets.find((t) => t.type === 'path') || o.targets[0]).value;
    fs.writeFileSync(o.sbom, require('./core/sbom').sbomJson(result, format, { name }), 'utf8');
    console.log(`SBOM (${format === 'spdx' ? 'SPDX 2.3' : 'CycloneDX 1.5'}, ${require('./core/sbom').packagesOf(result).length} Pakete) geschrieben: ${o.sbom}`);
  }

  // --fail-on <severity>: Exit-Code 2, wenn Befunde mit diesem Schweregrad oder hoeher existieren (fuer CI).
  // Ohne Angabe gilt failOn aus der Projektdatei (torvane.yml).
  if (!o.failOn && result.meta && result.meta.project && result.meta.project.failOn) o.failOn = result.meta.project.failOn;
  if (o.failOn) {
    // Test-Fixtures und Beispiele (devOnly) sollen keinen Build brechen; --fail-on-tests nimmt sie mit
    const counted = result.findings.filter((f) => !f.suppressed && (o.failOnTests || !f.devOnly));
    const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const f of counted) if (counts[f.severity] != null) counts[f.severity]++;
    const n = atOrAbove(counts, o.failOn);
    if (n > 0) {
      console.error(`\nAbbruch (--fail-on ${o.failOn}): ${n} Befund(e) mit Schweregrad >= ${o.failOn}.`);
      process.exit(2);
    }
  }
})().catch((e) => { console.error('Fehler:', e); process.exit(1); });
