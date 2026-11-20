'use strict';

// Anwendungs-Sicherheit ohne KI: Rechteprüfung in Routen, IDOR, CSRF, Rate-Limit, Uploads, SSRF ueber
// Variablen, XSS in React/Svelte, Electron-Haertung, Browser-Erweiterungen, Minecraft-Plugins,
// exportierte Android-Komponenten und Geheimnisse in CI-Workflows.
// Grundsatz gegen Fehlalarme: gemeldet wird nur mit Gegenbeleg (z. B. "andere Routen derselben Datei
// haben eine Anmeldung, diese nicht") oder bei eindeutigen Mustern.

const { base, fileName, mk, isText } = require('./rulekit');

const M = 'appsec-rules';
const JS = /\.(m?[jt]sx?|cjs)$/i;
const PY = /\.py$/i;
const JAVA = /\.(java|kt)$/i;

const AUTH_JS = /\b(auth\w*|requireAuth\w*|requireUser|requireLogin|requireSession|ensure\w*(?:Auth|Login)\w*|ensureLoggedIn|isAuthenticated|isLoggedIn|loggedIn|protect\w*|verifyToken|verifyJwt|jwtCheck|checkJwt|passport\.authenticate|authorize\w*|requireRole|requireAdmin|isAdmin|adminOnly|guard\w*|withAuth|withSession|requirePermission|can\w*)\b/i;
const AUTH_PY = /@(login_required|jwt_required|auth_required|roles_required|permission_required|requires_auth|token_required|admin_required|staff_member_required|user_passes_test)|Depends\(\s*(get_current_\w+|current_user|require_\w+|auth\w*)|current_user\b/;
const PUBLIC_PATH = /\/(login|logout|signin|sign-in|signup|sign-up|register|auth|oauth|callback|webhooks?|hooks?|health|healthz|ready|live|ping|status|metrics|public|reset|forgot|password-reset|verify|confirm|token|csp-report|robots|sitemap|favicon)(\/|$|\?|:)/i;
const STATE = /^(post|put|patch|delete|all)$/i;
const OWNER = /req\.user|request\.user|current_user|currentUser|session\.user|userId|user_id|ownerId|owner_id|\bowner\b|tenant|orgId|org_id|accountId|account_id|createdBy|created_by|authorId|author_id|isOwner|can\(|ability|policy|authorize|assertAccess|checkAccess|permission/i;

const ROUTE_JS = /\b(app|router|server|api|routes?|r|fastify)\.(get|post|put|patch|delete|all)\s*\(\s*(['"`])([^'"`\n]+)\3\s*,([^\n]*)/g;
const ROUTE_PY = /((?:^[ \t]*@[^\n]+\n)+)[ \t]*(?:async\s+)?def\s+(\w+)\s*\(([^)]*)\)/gm;

const lineAt = (c, i) => c.slice(c.lastIndexOf('\n', i - 1) + 1, c.indexOf('\n', i) < 0 ? c.length : c.indexOf('\n', i));
const isComment = (l) => /^\s*(\/\/|\/?\*|#)/.test(l);

// Routen einer Datei mit Methode, Pfad, Position und ob eine Anmeldung davorsteht
function routesOf(u) {
  const c = u.content || '';
  const out = [];
  if (JS.test(base(u))) {
    if (/\b(app|router)\.use\(\s*(?:['"`][^'"`]*['"`]\s*,\s*)?(?:\w+\.)?\w*(auth|requireUser|requireLogin|ensureLoggedIn|isAuthenticated|protect|verifyToken|checkJwt|passport\.authenticate|session)\w*/i.test(c)) out.global = true;
    ROUTE_JS.lastIndex = 0; let m;
    while ((m = ROUTE_JS.exec(c))) {
      if (isComment(lineAt(c, m.index))) continue;
      const handlers = m[5];
      const auth = AUTH_JS.test(handlers.replace(/\([^()]*\)\s*=>[\s\S]*$/, '').replace(/async\s*\(/, '('));
      out.push({ method: m[2].toLowerCase(), path: m[4], idx: m.index, auth, kind: 'js' });
    }
  } else if (PY.test(base(u))) {
    ROUTE_PY.lastIndex = 0; let m;
    while ((m = ROUTE_PY.exec(c))) {
      const dec = m[1];
      const r = dec.match(/@\w+\.(route|get|post|put|patch|delete|api_route)\(\s*['"]([^'"]+)['"]([^\n]*)/);
      if (!r) continue;
      let method = r[1] === 'route' || r[1] === 'api_route' ? 'get' : r[1];
      const methods = (r[3].match(/methods\s*=\s*\[([^\]]*)\]/) || [])[1] || '';
      if (/POST|PUT|PATCH|DELETE/i.test(methods)) method = (methods.match(/POST|PUT|PATCH|DELETE/i) || ['post'])[0].toLowerCase();
      const auth = AUTH_PY.test(dec) || AUTH_PY.test(m[3]);
      out.push({ method, path: r[2], idx: m.index, auth, kind: 'py', fn: m[2] });
    }
  }
  return out;
}

const F = {
  authz: {
    title: 'Route ohne Anmeldeprüfung, obwohl andere Routen dieser Datei eine haben',
    desc: 'Die Route {0} ändert Daten, hat aber keine Anmelde- oder Rechteprüfung. Andere Routen in derselben Datei prüfen die Anmeldung. Das deutet auf eine vergessene Prüfung hin.',
    fix: 'Die Anmelde- bzw. Rechteprüfung auch vor diese Route setzen oder sie für den ganzen Router einschalten. Falls die Route absichtlich öffentlich ist, das mit einer Ausnahme im Code begründen.',
    impact: 'Wer die Adresse kennt, kann die Aktion ohne Anmeldung ausführen.',
  },
  idor: {
    title: 'Datensatz über ID aus der Anfrage ohne Besitzerprüfung (IDOR-Verdacht)',
    desc: 'Der Datensatz wird nur über eine ID aus der Anfrage geladen oder geändert. In der Nähe ist keine Prüfung zu sehen, ob er dem angemeldeten Nutzer gehört.',
    fix: 'Den Besitzer mit in die Abfrage nehmen (z. B. where: { id, userId: req.user.id }) oder nach dem Laden prüfen, ob der Nutzer zugreifen darf.',
    impact: 'Durch Ändern der ID in der Adresse lassen sich fremde Datensätze lesen oder ändern.',
  },
  csrf: {
    title: 'Anmeldung per Cookie, aber kein Schutz gegen CSRF',
    desc: 'Die Anwendung nutzt eine Sitzung im Cookie und hat Routen, die Daten ändern. Ein CSRF-Schutz (Token oder SameSite-Cookie) ist im Projekt nicht zu finden.',
    fix: 'Das Sitzungs-Cookie mit sameSite: \'lax\' oder \'strict\' setzen und für Formulare ein CSRF-Token verwenden (z. B. csrf-csrf oder lusca).',
    impact: 'Eine fremde Webseite kann im Namen angemeldeter Nutzer Aktionen auslösen.',
  },
  rate: {
    title: 'Anmelde- und Passwort-Routen ohne Begrenzung der Versuche',
    desc: 'Routen für Anmeldung, Passwort oder Codes ({0}) haben keine Begrenzung der Versuche. Im Projekt ist kein Rate-Limiter zu finden.',
    fix: 'Einen Rate-Limiter vor diese Routen setzen (z. B. express-rate-limit, Flask-Limiter, slowapi) und nach mehreren Fehlversuchen bremsen.',
    impact: 'Passwörter und Einmal-Codes lassen sich in kurzer Zeit durchprobieren.',
  },
  uploadNoCheck: {
    title: 'Datei-Upload ohne Prüfung von Typ und Größe',
    desc: 'Der Upload nimmt jede Datei in beliebiger Größe an. Es gibt weder einen Dateifilter noch eine Größengrenze.',
    fix: 'fileFilter mit erlaubten Typen und limits: { fileSize } setzen; Dateien unter einem eigenen, zufälligen Namen speichern.',
    impact: 'Große oder schädliche Dateien landen auf dem Server.',
  },
  uploadPublic: {
    title: 'Hochgeladene Dateien landen im öffentlichen Web-Ordner',
    desc: 'Uploads werden in einem Ordner gespeichert, den der Webserver direkt ausliefert.',
    fix: 'Uploads außerhalb des Web-Ordners speichern und über eine geprüfte Route ausliefern; ausführbare Endungen sperren.',
    impact: 'Eine hochgeladene HTML- oder Skriptdatei wird direkt ausgeliefert oder sogar ausgeführt.',
  },
  uploadName: {
    title: 'Upload wird unter dem Dateinamen des Nutzers gespeichert',
    desc: 'Der Speicherpfad enthält den Originalnamen der hochgeladenen Datei. Namen wie ../../config.js führen aus dem Upload-Ordner heraus.',
    fix: 'Einen eigenen, zufälligen Dateinamen vergeben (bzw. secure_filename/basename verwenden) und die Endung gegen eine Liste prüfen.',
    impact: 'Bestehende Dateien auf dem Server lassen sich überschreiben.',
  },
  ssrf: {
    title: 'Server ruft eine Adresse aus der Anfrage ab, interne Ziele sind nicht gesperrt',
    desc: 'Eine Adresse aus der Anfrage wird über eine Variable an den Abruf weitergegeben. Eine Sperre für interne Netze und Cloud-Metadaten (169.254.169.254) ist in der Datei nicht zu sehen.',
    fix: 'Nur Adressen aus einer Liste erlaubter Hosts abrufen; die Ziel-IP nach der Namensauflösung gegen private Netze und 169.254.0.0/16 prüfen.',
    impact: 'Über den Server lassen sich interne Dienste und Cloud-Zugangsdaten abfragen.',
  },
  xss: {
    title: 'HTML wird ungefiltert in die Seite gesetzt (React/Svelte)',
    desc: 'Ein Wert wird als rohes HTML eingefügt ({0}), ohne dass eine Bereinigung zu sehen ist.',
    fix: 'Den Wert vorher mit DOMPurify bereinigen oder als Text statt als HTML ausgeben.',
    impact: 'Kommt der Wert von Nutzern, kann darüber Skriptcode in der Seite laufen.',
  },
  electronFlag: {
    title: 'Electron-Fenster mit abgeschalteter Schutzfunktion: {0}',
    desc: 'In den webPreferences eines Fensters ist {0} gesetzt. Damit fällt eine der wichtigsten Schutzschichten von Electron weg.',
    fix: 'Die Einstellung entfernen bzw. auf den sicheren Wert setzen (nodeIntegration: false, contextIsolation: true, sandbox: true, webSecurity: true) und benötigte Funktionen über ein Preload-Skript anbieten.',
    impact: 'Fremder Inhalt im Fenster (z. B. durch XSS) erhält Zugriff auf den Rechner.',
  },
  electronNav: {
    title: 'Electron-Fenster lädt Webinhalte, fängt Navigation und neue Fenster aber nicht ab',
    desc: 'Das Fenster lädt eine Webadresse, aber weder setWindowOpenHandler noch ein will-navigate-Handler begrenzen, wohin es wechseln darf.',
    fix: 'webContents.setWindowOpenHandler und einen will-navigate-Handler setzen, die nur eigene Adressen zulassen und den Rest im Browser öffnen.',
    impact: 'Ein Link oder eine Umleitung bringt fremde Seiten in das App-Fenster.',
  },
  electronExternal: {
    title: 'shell.openExternal mit ungeprüfter Adresse',
    desc: 'shell.openExternal öffnet eine Adresse aus einer Variablen, ohne vorher das Protokoll zu prüfen.',
    fix: 'Vorher prüfen, dass die Adresse mit https: beginnt (new URL(x).protocol === \'https:\'), alles andere ablehnen.',
    impact: 'Adressen wie file: oder eigene Protokolle können Programme auf dem Rechner starten.',
  },
  electronIpc: {
    title: 'IPC-Nachricht aus dem Fenster steuert eine heikle Aktion ohne Prüfung',
    desc: 'Ein ipcMain-Handler übergibt einen Wert aus dem Fenster direkt an {0}. Der Absender und der Wert werden nicht geprüft.',
    fix: 'Im Handler den Absender (event.senderFrame.url) prüfen und den Wert gegen eine Liste erlaubter Werte abgleichen.',
    impact: 'Schadcode im Fenster kann darüber Befehle oder Dateizugriffe im Hauptprozess auslösen.',
  },
  extAll: {
    title: 'Browser-Erweiterung darf alle Webseiten lesen und verändern',
    desc: 'Die Erweiterung verlangt Zugriff auf alle Seiten ({0}).',
    fix: 'Nur die Seiten eintragen, die die Erweiterung wirklich braucht, oder activeTab bzw. optionale Berechtigungen verwenden.',
    impact: 'Eine Lücke in der Erweiterung betrifft damit jede besuchte Webseite, auch Online-Banking.',
  },
  extCsp: {
    title: 'Browser-Erweiterung erlaubt {0} in ihrer Content-Security-Policy',
    desc: 'Die Sicherheitsrichtlinie der Erweiterung lässt {0} zu.',
    fix: 'unsafe-eval und unsafe-inline aus der content_security_policy entfernen; Code nur aus eigenen Dateien laden.',
    impact: 'Eingeschleuster Text kann als Code im Kontext der Erweiterung laufen.',
  },
  extConnect: {
    title: 'Jede Webseite darf Nachrichten an die Erweiterung schicken',
    desc: 'externally_connectable erlaubt Verbindungen von allen Seiten.',
    fix: 'In externally_connectable nur die eigenen Domains eintragen.',
    impact: 'Fremde Webseiten können Funktionen der Erweiterung aufrufen.',
  },
  mcCommand: {
    title: 'Minecraft-Befehl führt eine heikle Aktion ohne Rechteprüfung aus',
    desc: 'onCommand ruft {0} auf, prüft aber nirgends hasPermission oder isOp.',
    fix: 'Am Anfang des Befehls sender.hasPermission("plugin.befehl") prüfen und die Berechtigung in plugin.yml eintragen.',
    impact: 'Jeder Spieler kann die Aktion auslösen.',
  },
  mcDispatch: {
    title: 'Spielereingabe landet in einem Server-Befehl',
    desc: 'Argumente eines Befehls werden in dispatchCommand eingesetzt.',
    fix: 'Die Argumente gegen erlaubte Werte prüfen (z. B. nur gültige Spielernamen) statt sie in einen Konsolenbefehl einzusetzen.',
    impact: 'Spieler können beliebige Konsolenbefehle mit Server-Rechten ausführen.',
  },
  mcYmlPerm: {
    title: 'Plugin-Befehle ohne Berechtigung in plugin.yml: {0}',
    desc: 'Diese Befehle haben in plugin.yml keinen Eintrag permission. Ob sie geschützt sind, hängt allein vom Code ab.',
    fix: 'Für jeden Befehl permission: plugin.befehl eintragen und im Code prüfen.',
    impact: 'Vergessene Prüfungen im Code fallen nicht auf.',
  },
  mcPassword: {
    title: 'Klartext-Passwort in der Plugin-Konfiguration',
    desc: 'In der config.yml eines Plugins steht ein Passwort im Klartext.',
    fix: 'Das Passwort aus der Datei nehmen, über eine Umgebungsvariable einlesen und die Datei mit Beispielwert ausliefern.',
    impact: 'Wer die Server-Dateien oder ein Backup sieht, kennt das Datenbank-Passwort.',
  },
  androidExported: {
    title: 'Android-Komponente ist für andere Apps offen: {0}',
    desc: 'Die Komponente {0} ist mit android:exported="true" freigegeben und verlangt keine Berechtigung.',
    fix: 'android:exported="false" setzen oder mit android:permission eine eigene Berechtigung verlangen.',
    impact: 'Jede andere App auf dem Gerät kann die Komponente starten und ihr Daten schicken.',
  },
  ciSecret: {
    title: 'Workflow kann ein Geheimnis im Log ausgeben',
    desc: 'Ein Schritt verarbeitet ein Geheimnis so, dass GitHub es im Log nicht mehr schwärzen kann ({0}).',
    fix: 'Geheimnisse nie ausgeben oder umwandeln; set -x in Schritten mit Geheimnissen entfernen.',
    impact: 'Jeder mit Lesezugriff auf die Actions-Logs sieht das Geheimnis.',
  },
  ciDebug: {
    title: 'Debug-Protokoll der Actions dauerhaft eingeschaltet',
    desc: 'ACTIONS_STEP_DEBUG bzw. ACTIONS_RUNNER_DEBUG ist fest eingeschaltet.',
    fix: 'Debug-Protokolle nur kurzzeitig zur Fehlersuche einschalten.',
    impact: 'Ausführliche Protokolle enthalten oft interne Details.',
  },
};
const fill = (s, ...v) => s.replace(/\{(\d)\}/g, (x, i) => v[Number(i)] ?? '');

function push(out, u, idx, key, sev, cat, vals = [], ev = '', conf = 'medium') {
  const t = F[key];
  out.push(mk(M, u, idx, {
    ruleId: 'appsec-' + key.replace(/[A-Z]/g, (x) => '-' + x.toLowerCase()), severity: sev, category: cat, confidence: conf,
    title: fill(t.title, ...vals), description: fill(t.desc, ...vals), remediation: t.fix, impact: t.impact,
    evidence: String(ev).replace(/\s+/g, ' ').trim().slice(0, 160),
  }));
}

// --- Web-Anwendungen -------------------------------------------------------
function webApp(units, out) {
  const code = units.filter((u) => isText(u) && (JS.test(base(u)) || PY.test(base(u))));
  const all = code.map((u) => u.content).join('\n');
  const sensitive = [];
  let sessionUnit = null, stateRoutes = 0;
  for (const u of code) {
    const c = u.content;
    const routes = routesOf(u);
    // 1. Fehlende Anmeldung im Vergleich zu den Nachbarrouten
    if (!routes.global && routes.some((r) => r.auth)) {
      let n = 0;
      for (const r of routes) if (!r.auth && STATE.test(r.method) && !PUBLIC_PATH.test(r.path) && n++ < 5) push(out, u, r.idx, 'authz', 'high', 'AccessControl', [`${r.method.toUpperCase()} ${r.path}`], lineAt(c, r.idx));
    }
    stateRoutes += routes.filter((r) => STATE.test(r.method)).length;
    for (const r of routes) if (/(login|signin|sign-in|token|reset|forgot|password|otp|2fa|mfa|verify|register|signup)/i.test(r.path)) sensitive.push({ u, r });
    if (!sessionUnit && JS.test(base(u)) && /require\(\s*['"](express-session|cookie-session)['"]\)|from\s+['"](express-session|cookie-session)['"]/.test(c)) sessionUnit = u;
    // 2. IDOR: Laden/Aendern per ID aus der Anfrage ohne Besitzer in der Naehe
    if (routes.length) {
      const re = /\b(findById|findByPk|findOne|findUnique|findFirst|findOneAndUpdate|findByIdAndUpdate|findByIdAndDelete|deleteOne|updateOne|destroy|get_object_or_404|query\.get|objects\.get)\s*\(\s*[^;\n]{0,60}?\b(req\.params\.\w+|req\.query\.\w+|request\.args\[?\.?\w*|pk\s*=\s*\w+|id\s*=\s*\w+)/g;
      let m, n = 0;
      while ((m = re.exec(c)) && n < 3) {
        // Fenster nur innerhalb der eigenen Route (Nachbarrouten mit req.user zaehlen nicht)
        const start = Math.max(0, m.index - 500, ...routes.filter((r) => r.idx <= m.index).map((r) => r.idx));
        const nextRoute = routes.find((r) => r.idx > m.index);
        const win = c.slice(start, Math.min(m.index + 300, nextRoute ? nextRoute.idx : c.length));
        if (OWNER.test(win) || isComment(lineAt(c, m.index))) continue;
        n++;
        push(out, u, m.index, 'idor', 'medium', 'AccessControl', [], lineAt(c, m.index), 'low');
      }
    }
    // 3. Uploads
    let m;
    const mu = /\bmulter\s*\(\s*(\{[\s\S]{0,400}?\})?\s*\)/g;
    while ((m = mu.exec(c))) {
      const opts = m[1] || '';
      if (/(dest|destination)\s*:\s*['"`][^'"`]*\b(public|static|www|htdocs|wwwroot)\b/i.test(opts)) push(out, u, m.index, 'uploadPublic', 'high', 'Config', [], m[0]);
      else if (!/fileFilter|limits/.test(opts) && !/fileFilter|limits\s*:/.test(c.slice(m.index, m.index + 1500))) push(out, u, m.index, 'uploadNoCheck', 'medium', 'Config', [], m[0], 'low');
    }
    const nameRe = /\.mv\s*\(\s*[^,)]*\.name\b|\.save\s*\(\s*os\.path\.join\([^)]*\.filename\s*\)|move_uploaded_file\s*\([^,]+,\s*[^)]*\$_FILES\s*\[[^\]]+\]\s*\[\s*['"]name['"]\s*\]/g;
    while ((m = nameRe.exec(c))) if (!/secure_filename|basename|randomUUID|uuid|crypto\.random/.test(c.slice(Math.max(0, m.index - 400), m.index + 200))) push(out, u, m.index, 'uploadName', 'high', 'PathTraversal', [], m[0]);
    // 4. SSRF ueber eine Variable aus der Anfrage
    const varRe = /\b(?:const|let|var)?\s*(\w*(?:url|uri|link|webhook|callback|target|endpoint|src|href|feed|image)\w*)\s*=\s*(?:req\.(?:body|query|params)\.\w+|request\.(?:args|form|json|values|GET|POST|data)(?:\.get\(|\[)['"]?\w+)/gi;
    if (!/169\.254|isPrivate|private.?(ip|address|range)|ipaddr|ssrf|allow.?list|allowedHosts|blockPrivate|isInternal|is_private|ipaddress\.ip_address/i.test(c)) {
      while ((m = varRe.exec(c))) {
        const v = m[1];
        const after = c.slice(m.index, m.index + 1500);
        const call = new RegExp(`\\b(fetch|axios(?:\\.get|\\.post)?|got|needle|http\\.get|https\\.get|requests\\.(?:get|post)|httpx\\.(?:get|post)|urlopen)\\s*\\(\\s*${v}\\b`).exec(after);
        if (call) { push(out, u, m.index + call.index, 'ssrf', 'high', 'SSRF', [], lineAt(c, m.index + call.index)); break; }
      }
    }
    // 5. XSS in React/Svelte
    const xr = /dangerouslySetInnerHTML\s*=\s*\{\{\s*__html\s*:\s*([^}]+)\}\}|\{@html\s+([^}]+)\}/g;
    let nx = 0;
    while ((m = xr.exec(c)) && nx < 3) {
      const expr = (m[1] || m[2]).trim();
      if (/^['"`][^$]*['"`]$/.test(expr) || /sanitiz|purify|escape|xss|safe|clean|i18n|\bt\(/i.test(expr)) continue;
      nx++;
      push(out, u, m.index, 'xss', 'medium', 'XSS', [m[1] ? 'dangerouslySetInnerHTML' : '{@html}'], m[0], 'low');
    }
  }
  // 6. CSRF auf Projektebene
  if (sessionUnit && stateRoutes && !/\bcsurf\b|csrf|lusca|xsrf|sameSite\s*:\s*['"`]?(strict|lax)|double.?submit/i.test(all)) push(out, sessionUnit, sessionUnit.content.search(/express-session|cookie-session/), 'csrf', 'medium', 'AccessControl', [], 'express-session ohne CSRF-Schutz', 'low');
  // 7. Rate-Limit auf Projektebene
  if (sensitive.length) {
    const deps = units.filter((u) => /(^|\/)(package\.json|requirements[^/]*\.txt|pyproject\.toml|Pipfile)$/i.test(base(u))).map((u) => u.content).join('\n');
    if (!/rate.?limit|ratelimit|rate-limiter|slow.?down|limiter|throttl|bottleneck|@limits\(|slowapi|brute/i.test(all + deps)) {
      const s = sensitive[0];
      push(out, s.u, s.r.idx, 'rate', 'medium', 'Auth', [sensitive.slice(0, 4).map((x) => `${x.r.method.toUpperCase()} ${x.r.path}`).join(', ')], lineAt(s.u.content, s.r.idx), 'low');
    }
  }
}

// --- Electron --------------------------------------------------------------
function electron(units, out) {
  for (const u of units) {
    if (!isText(u) || !JS.test(base(u))) continue;
    const c = u.content;
    if (!/require\(\s*['"]electron['"]\)|from\s+['"]electron['"]/.test(c)) continue;
    const flags = [
      [/nodeIntegration\s*:\s*true/, 'nodeIntegration: true', 'high'],
      [/nodeIntegrationInSubFrames\s*:\s*true/, 'nodeIntegrationInSubFrames: true', 'high'],
      [/contextIsolation\s*:\s*false/, 'contextIsolation: false', 'high'],
      [/webSecurity\s*:\s*false/, 'webSecurity: false', 'high'],
      [/enableRemoteModule\s*:\s*true/, 'enableRemoteModule: true', 'high'],
      [/sandbox\s*:\s*false/, 'sandbox: false', 'medium'],
      [/webviewTag\s*:\s*true/, 'webviewTag: true', 'medium'],
      [/allowRunningInsecureContent\s*:\s*true/, 'allowRunningInsecureContent: true', 'medium'],
    ];
    for (const [re, name, sev] of flags) { const i = c.search(re); if (i >= 0 && !isComment(lineAt(c, i))) push(out, u, i, 'electronFlag', sev, 'Config', [name], lineAt(c, i)); }
    const remote = c.search(/\.loadURL\s*\(\s*['"`]https?:\/\/(?!localhost|127\.0\.0\.1|\[::1\])/);
    if (remote >= 0 && /new\s+BrowserWindow/.test(c) && !/setWindowOpenHandler|['"]new-window['"]/.test(c) && !/will-navigate/.test(c)) push(out, u, remote, 'electronNav', 'low', 'Config', [], lineAt(c, remote), 'low');
    let m;
    const oe = /shell\.openExternal\s*\(\s*(?!['"`])([\w.$[\]]+)/g;
    while ((m = oe.exec(c))) {
      const v = m[1];
      const before = c.slice(Math.max(0, m.index - 400), m.index);
      if (/^[A-Z0-9_.]+$/.test(v.split('.').pop()) || /(^|\.)[A-Z][A-Z0-9_]{2,}$/.test(v)) continue; // Konstante
      if (/protocol|startsWith\(\s*['"]https?:|new URL\(|allow|isSafe|isTrusted|ALLOWED|\/\^[a-z]+[:\\]|\.test\(/i.test(before)) continue;
      push(out, u, m.index, 'electronExternal', 'low', 'Config', [], lineAt(c, m.index), 'low'); break;
    }
    const ipc = /ipcMain\.(?:handle|on)\s*\(\s*['"][^'"]+['"]\s*,\s*(?:async\s*)?(?:function\s*)?\(?\s*\w+\s*,\s*(\w+)[^)]*\)?\s*=?>?\s*\{/g;
    while ((m = ipc.exec(c))) {
      const arg = m[1];
      const body = c.slice(m.index, m.index + 600);
      const sink = new RegExp(`\\b(exec|execSync|spawn|execFile|shell\\.openExternal|fs\\.(?:writeFile|writeFileSync|rm|rmSync|unlink|unlinkSync)|require)\\s*\\(\\s*${arg}\\b`).exec(body);
      if (sink && !/senderFrame|sender\.getURL|validate|allowed|includes\(|ALLOWED/i.test(body.slice(0, sink.index))) push(out, u, m.index, 'electronIpc', 'high', 'Injection', [sink[1]], lineAt(c, m.index));
    }
  }
}

// --- Browser-Erweiterungen --------------------------------------------------
function browserExt(units, out) {
  for (const u of units) {
    if (!isText(u) || fileName(u) !== 'manifest.json') continue;
    let j; try { j = JSON.parse(u.content); } catch { continue; }
    if (!j || !j.manifest_version || !(j.background || j.content_scripts || j.action || j.browser_action)) continue;
    const ALL = (p) => /^(<all_urls>|\*:\/\/\*\/\*|https?:\/\/\*\/\*|\*:\/\/\*\/)$/.test(String(p));
    const perms = [...(j.host_permissions || []), ...(j.permissions || []), ...((j.content_scripts || []).flatMap((s) => s.matches || []))];
    const wide = perms.filter(ALL);
    if (wide.length) push(out, u, u.content.indexOf(wide[0]), 'extAll', 'medium', 'AccessControl', [[...new Set(wide)].join(', ')], wide[0]);
    const csp = typeof j.content_security_policy === 'string' ? j.content_security_policy : JSON.stringify(j.content_security_policy || '');
    if (/unsafe-eval/.test(csp)) push(out, u, u.content.indexOf('unsafe-eval'), 'extCsp', 'high', 'Config', ["'unsafe-eval'"], 'unsafe-eval');
    else if (/unsafe-inline/.test(csp)) push(out, u, u.content.indexOf('unsafe-inline'), 'extCsp', 'medium', 'Config', ["'unsafe-inline'"], 'unsafe-inline');
    const ec = j.externally_connectable || {};
    if ((ec.matches || []).some(ALL) || (ec.ids || []).includes('*')) push(out, u, u.content.indexOf('externally_connectable'), 'extConnect', 'high', 'AccessControl', [], 'externally_connectable');
  }
}

// --- Minecraft-Plugins -------------------------------------------------------
function minecraft(units, out) {
  const DANGER = /\b(setOp|dispatchCommand|banPlayer|kickPlayer|\.ban\(|setGameMode|\.shutdown\(|setHealth|executeUpdate|createStatement|setWhitelisted|getBanList|deleteWorld|unloadWorld|Files\.delete)\b/;
  for (const u of units) {
    if (!isText(u)) continue;
    const c = u.content;
    if (JAVA.test(base(u)) && /onCommand\s*\(/.test(c)) {
      const re = /(?:public\s+)?(?:boolean|fun|override\s+fun)\s+onCommand\s*\(/g; let m;
      while ((m = re.exec(c))) {
        const open = c.indexOf('{', m.index);
        if (open < 0) continue;
        let d = 0, i = open;
        for (; i < c.length; i++) { if (c[i] === '{') d++; else if (c[i] === '}' && --d === 0) break; }
        const body = c.slice(open, i);
        const disp = /dispatchCommand\s*\([^;]*(\+\s*args\s*\[|\$\{?args|String\.join\([^)]*args|format\([^)]*args)/.exec(body);
        if (disp) push(out, u, open + disp.index, 'mcDispatch', 'high', 'Injection', [], disp[0]);
        const dg = DANGER.exec(body);
        if (dg && !/hasPermission|isOp\(|\.permission|getPermission|checkPermission|PermissionDefault|requirePermission/.test(body)) push(out, u, open + dg.index, 'mcCommand', 'medium', 'AccessControl', [dg[1]], lineAt(c, open + dg.index), 'low');
      }
    }
    if (fileName(u) === 'plugin.yml' && !String(u.label).includes('!/') && /^main\s*:/m.test(c) && /^commands\s*:/m.test(c)) {
      const block = c.slice(c.search(/^commands\s*:/m)).split(/\n(?=\S)/)[0];
      const cmds = [...block.matchAll(/^ {2}([\w-]+)\s*:\s*\n((?: {4,}[^\n]*\n?)*)/gm)].filter((x) => !/permission\s*:/.test(x[2])).map((x) => x[1]);
      if (cmds.length) push(out, u, c.search(/^commands\s*:/m), 'mcYmlPerm', 'low', 'AccessControl', [cmds.slice(0, 6).join(', ')], 'commands:', 'low');
    }
    if (fileName(u) === 'config.yml' && units.some((x) => fileName(x) === 'plugin.yml' && base(x).replace(/[^/]+$/, '') === base(u).replace(/[^/]+$/, ''))) {
      const m = /^\s*password\s*:\s*(?!''|""|~|null|\$\{|<|changeme|password\b)['"]?([^\s'"#]{4,})/im.exec(c);
      if (m) push(out, u, m.index, 'mcPassword', 'medium', 'Secrets', [], 'password: ****');
    }
  }
}

// --- Android: exportierte Komponenten ohne Berechtigung ------------------------
function android(units, out) {
  for (const u of units) {
    if (!isText(u) || fileName(u) !== 'androidmanifest.xml') continue;
    const c = u.content;
    const re = /<(activity|activity-alias|service|receiver|provider)\b([^>]*)>([\s\S]*?)<\/\1>|<(activity|activity-alias|service|receiver|provider)\b([^>]*)\/>/g; let m, n = 0;
    while ((m = re.exec(c)) && n < 5) {
      const attrs = m[2] || m[5] || '';
      const inner = m[3] || '';
      if (!/android:exported\s*=\s*["']true["']/.test(attrs) || /android:(permission|readPermission|writePermission)\s*=/.test(attrs)) continue;
      if (/android\.intent\.category\.LAUNCHER|android\.intent\.action\.MAIN/.test(inner)) continue;
      const name = (attrs.match(/android:name\s*=\s*["']([^"']+)["']/) || [])[1] || (m[1] || m[4]);
      n++;
      push(out, u, m.index, 'androidExported', (m[1] || m[4]) === 'provider' ? 'high' : 'medium', 'AccessControl', [name], `<${m[1] || m[4]} android:name="${name}" android:exported="true">`);
    }
  }
}

// --- Geheimnisse in CI-Workflows ----------------------------------------------
function ciSecrets(units, out) {
  for (const u of units) {
    if (!isText(u) || !/(^|\/)\.github\/workflows\/[^/]+\.ya?ml$/i.test(base(u))) continue;
    const c = u.content;
    let m;
    const tr = /\$\{\{\s*secrets\.\w+\s*\}\}[^\n]*\|\s*(base64|xxd|od|rev|tr|sed|awk|cut)\b|\b(base64|xxd)\b[^\n]*\$\{\{\s*secrets\./g;
    while ((m = tr.exec(c))) { push(out, u, m.index, 'ciSecret', 'high', 'Secrets', ['umgewandelt'], m[0]); break; }
    const steps = c.split(/\n\s*-\s+(?=name:|uses:|run:)/);
    let pos = 0;
    for (const s of steps) {
      if (/secrets\.\w+/.test(s) && /^\s*set\s+-[a-z]*x/m.test(s)) { push(out, u, c.indexOf(s, pos), 'ciSecret', 'medium', 'Secrets', ['set -x'], 'set -x'); break; }
      pos += s.length;
    }
    const dbg = c.search(/ACTIONS_(STEP|RUNNER)_DEBUG\s*:\s*['"]?true/i);
    if (dbg >= 0) push(out, u, dbg, 'ciDebug', 'low', 'Config', [], lineAt(c, dbg));
  }
}

function runAppSec(units) {
  const out = [];
  webApp(units, out);
  electron(units, out);
  browserExt(units, out);
  minecraft(units, out);
  android(units, out);
  ciSecrets(units, out);
  return out;
}

module.exports = { runAppSec, routesOf, TEXTS: F };
