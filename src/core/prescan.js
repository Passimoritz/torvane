'use strict';

// Prescan: schnelle statische Heuristiken OHNE KI.
// Liefert (a) direkte Befunde (z.B. Secrets - zu wichtig, um sie der KI zu ueberlassen)
// und (b) "Fakten", die als Kontext mit in den KI-Prompt gegeben werden.

const { normalizeFinding, redactSecret } = require('./schema');
const { findHighEntropy } = require('./entropy');
const { fsaudit } = require('./fsaudit');

// --- Secret-Muster ------------------------------------------------------
const SECRET_RULES = [
  { name: 'Private Key Block', re: /-----BEGIN (?:RSA |EC |OPENSSH |PGP |DSA )?PRIVATE KEY-----/g, sev: 'critical' },
  { name: 'AWS Access Key ID', re: /\bAKIA[0-9A-Z]{16}\b/g, sev: 'critical' },
  { name: 'AWS Secret Access Key', re: /\baws_secret_access_key\s*[=:]\s*['"]?[A-Za-z0-9/+=]{40}['"]?/gi, sev: 'critical' },
  { name: 'Google API Key', re: /\bAIza[0-9A-Za-z\-_]{35}\b/g, sev: 'high' },
  { name: 'Slack Token', re: /\bxox[baprs]-[0-9A-Za-z-]{10,}\b/g, sev: 'high' },
  { name: 'GitHub Token', re: /\bgh[pousr]_[0-9A-Za-z]{36,}\b/g, sev: 'high' },
  { name: 'OpenAI Key', re: /\bsk-[A-Za-z0-9]{20,}\b/g, sev: 'high' },
  { name: 'Anthropic Key', re: /\bsk-ant-[A-Za-z0-9\-_]{20,}\b/g, sev: 'high' },
  { name: 'JWT', re: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g, sev: 'medium' },
  { name: 'Generisches Passwort/Secret im Klartext', re: /\b(?:password|passwd|secret|api[_-]?key|token|client[_-]?secret)\s*[=:]\s*['"][^'"\n]{6,}['"]/gi, sev: 'high' },
  { name: 'DB Connection String mit Passwort', re: /\b(?:mongodb|postgres(?:ql)?|mysql|redis):\/\/[^\s:@/]+:[^\s:@/]+@/gi, sev: 'high' },
  { name: 'Stripe Secret Key (live)', re: /\b(?:sk|rk)_live_[0-9A-Za-z]{10,}\b/g, sev: 'critical' },
  { name: 'Stripe Publishable Key (live)', re: /\bpk_live_[0-9A-Za-z]{10,}\b/g, sev: 'low' },
  { name: 'SendGrid API Key', re: /\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b/g, sev: 'high' },
  { name: 'Mailgun API Key', re: /\bkey-[0-9a-f]{32}\b/g, sev: 'high' },
  { name: 'Twilio Account SID', re: /\bAC[0-9a-f]{32}\b/g, sev: 'medium' },
  { name: 'GitHub Fine-grained Token', re: /\bgithub_pat_[0-9A-Za-z_]{20,}\b/g, sev: 'high' },
  { name: 'npm Token', re: /\bnpm_[0-9A-Za-z]{36}\b/g, sev: 'high' },
  { name: 'Discord Bot Token', re: /\b[MNO][A-Za-z\d]{23,25}\.[\w-]{6}\.[\w-]{27,38}\b/g, sev: 'medium' },
  { name: 'Azure Storage AccountKey', re: /AccountKey=[A-Za-z0-9+/=]{40,}/g, sev: 'high' },
  { name: 'Zugangsdaten in URL', re: /\bhttps?:\/\/[^\s:@/"']+:[^\s:@/"']+@[^\s/"']+/gi, sev: 'high' },
  { name: 'Slack Webhook URL', re: /https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9/_+-]{20,}/g, sev: 'medium' },
  { name: 'Hartkodierter Basic-Auth-Header', re: /Authorization["'\s:]+Basic\s+[A-Za-z0-9+/=]{8,}/gi, sev: 'medium' },
];

// --- Riskante Code-Muster (sprachuebergreifend, heuristisch) ------------
const PATTERN_RULES = [
  { cat: 'Injection', name: 'Shell-Ausfuehrung mit moeglicher Eingabe', re: /\b(?:child_process|exec|execSync|spawn|popen|system|Runtime\.getRuntime\(\)\.exec|subprocess\.(?:call|run|Popen)|os\.system)\b/g, sev: 'high' },
  { cat: 'Injection', name: 'Dynamische Code-Ausfuehrung (eval/Function)', re: /\b(?:eval\s*\(|new\s+Function\s*\(|exec\s*\()/g, sev: 'high' },
  { cat: 'Injection', name: 'SQL-Konkatenation', re: /["'`]\s*(?:SELECT|INSERT|UPDATE|DELETE|DROP)\b[^;]*["'`]\s*\+/gi, sev: 'high' },
  { cat: 'XSS', name: 'Direktes DOM-HTML-Setzen', re: /\b(?:innerHTML|outerHTML|insertAdjacentHTML|document\.write|dangerouslySetInnerHTML)\b/g, sev: 'medium' },
  { cat: 'Deserialization', name: 'Unsichere Deserialisierung', re: /\b(?:pickle\.loads|yaml\.load\s*\((?![^)]*Loader)|readObject\s*\(|Marshal\.load|unserialize\s*\()/g, sev: 'high' },
  { cat: 'Crypto', name: 'Schwacher Hash (MD5/SHA1)', re: /\b(?:md5|sha1)\b/gi, sev: 'medium' },
  { cat: 'Crypto', name: 'Unsichere Zufallsquelle', re: /\bMath\.random\s*\(/g, sev: 'low' },
  { cat: 'Transport', name: 'TLS-Pruefung deaktiviert', re: /\b(?:rejectUnauthorized\s*:\s*false|verify\s*=\s*False|InsecureSkipVerify\s*:\s*true|CURLOPT_SSL_VERIFYPEER\s*,\s*(?:0|false))\b/gi, sev: 'high' },
  { cat: 'Transport', name: 'Klartext-HTTP-URL', re: /\bhttp:\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0)[^\s"'`]+/g, sev: 'low' },
  { cat: 'PathTraversal', name: 'Pfad aus Eingabe', re: /\.\.[\\/]/g, sev: 'low' },
  { cat: 'Config', name: 'Debug/Entwicklungsmodus aktiv', re: /\b(?:DEBUG\s*=\s*True|app\.debug\s*=\s*True|NODE_ENV\s*===?\s*['"]development['"])\b/g, sev: 'low' },
  { cat: 'AccessControl', name: 'Alles-erlaubt CORS', re: /Access-Control-Allow-Origin["'\s:]+\*/g, sev: 'medium' },
  { cat: 'Config', name: 'Electron: nodeIntegration aktiviert', re: /nodeIntegration\s*:\s*true/g, sev: 'high' },
  { cat: 'Config', name: 'Electron: contextIsolation deaktiviert', re: /contextIsolation\s*:\s*false/g, sev: 'high' },
  { cat: 'Config', name: 'Electron: webSecurity deaktiviert', re: /webSecurity\s*:\s*false/g, sev: 'high' },
  { cat: 'Config', name: 'Electron: unsichere Inhalte erlaubt', re: /allowRunningInsecureContent\s*:\s*true/g, sev: 'medium' },
  { cat: 'Crypto', name: 'Krypto ohne IV (createCipher)', re: /\bcreateCipher\s*\(/g, sev: 'medium' },
  { cat: 'Crypto', name: 'Schwache Chiffre (DES/RC4/ECB)', re: /\b(?:DES|3DES|RC4)\b|\becb\b/gi, sev: 'medium' },
  { cat: 'Injection', name: 'Shell mit shell=True (Python)', re: /shell\s*=\s*True/g, sev: 'high' },
  { cat: 'Injection', name: 'NoSQL $where-Operator', re: /\$where["'\s]*:/g, sev: 'medium' },
  { cat: 'Deserialization', name: 'XML-Parser (auf XXE pruefen)', re: /\b(?:DocumentBuilderFactory|SAXParser|XMLReader|etree\.parse|simplexml_load)/g, sev: 'low' },
  { cat: 'Auth', name: 'JWT-Algorithmus "none"', re: /alg[a-z]*\s*[:=]\s*\[?\s*['"]none['"]/gi, sev: 'high' },
  { cat: 'Auth', name: 'Hartkodierter SECRET_KEY', re: /SECRET_KEY\s*[=:]\s*["'][^"']{6,}["']/g, sev: 'high' },
  { cat: 'AccessControl', name: 'Open Redirect aus Eingabe', re: /(?:res\.redirect|location\.href\s*=|sendRedirect)\s*\(?\s*(?:req\.|request\.|params|query)/g, sev: 'medium' },
  { cat: 'Config', name: 'Cookie unsicher (httpOnly/secure false)', re: /(?:httpOnly|secure)\s*:\s*false/gi, sev: 'low' },
  { cat: 'Logging', name: 'Fehlerdetails/Stacktrace nach aussen', re: /\b(?:printStackTrace|traceback\.print_exc)\b|res\.(?:send|json)\s*\(\s*(?:err|error)\b/g, sev: 'low' },
  // Java / Spring
  { cat: 'AccessControl', name: 'Spring: CSRF deaktiviert', re: /csrf\(\)\s*\.\s*disable\(\)/g, sev: 'high' },
  { cat: 'AccessControl', name: 'Spring: CORS-Wildcard', re: /@CrossOrigin\s*\(\s*origins\s*=\s*["']\*["']|setAllowedOrigins\s*\([^)]*["']\*["']/g, sev: 'medium' },
  { cat: 'Injection', name: 'Java: ProcessBuilder', re: /new\s+ProcessBuilder\s*\(/g, sev: 'medium' },
  { cat: 'Transport', name: 'Java: alle Zertifikate/Hosts akzeptiert', re: /ALLOW_ALL_HOSTNAME_VERIFIER|TrustAllCerts|NoopHostnameVerifier/g, sev: 'high' },
  // Go
  { cat: 'XSS', name: 'Go: template.HTML (ungefiltertes HTML)', re: /template\.HTML\s*\(/g, sev: 'medium' },
  // Ruby / Rails: rules/rails.yml
  // PHP
  { cat: 'Injection', name: 'PHP: Eingabe in Query/Exec', re: /(?:->query|mysqli_query|shell_exec|\bsystem|\bexec)\s*\([^)]*\$_(?:GET|POST|REQUEST|COOKIE)/g, sev: 'high' },
  { cat: 'Injection', name: 'PHP: LFI/RFI (include aus Eingabe)', re: /(?:include|require)(?:_once)?\s*\(?\s*\$_(?:GET|POST|REQUEST)/g, sev: 'high' },
  { cat: 'Injection', name: 'PHP: extract($_...)', re: /extract\s*\(\s*\$_(?:GET|POST|REQUEST)/g, sev: 'medium' },
  // C# / .NET
  { cat: 'Injection', name: '.NET: SqlCommand mit Konkatenation', re: /new\s+SqlCommand\s*\([^)]*\+/g, sev: 'high' },
  { cat: 'Deserialization', name: '.NET: BinaryFormatter', re: /\bBinaryFormatter\b/g, sev: 'high' },
  { cat: 'Transport', name: '.NET: Zertifikatspruefung umgangen', re: /ServerCertificateValidationCallback\s*[+=]/g, sev: 'high' },
  { cat: 'XSS', name: '.NET: Html.Raw', re: /Html\.Raw\s*\(/g, sev: 'medium' },
  // Python / Django: rules/django.yml
  // Allgemein
  { cat: 'Auth', name: 'Hartkodiertes JWT-Secret', re: /jwt\.(?:sign|verify|encode|decode)\s*\([^)]*,\s*["'][^"']{4,}["']/g, sev: 'medium' },
  // Docker
  { cat: 'Config', name: 'Docker: unpinntes Basis-Image (:latest)', re: /^\s*FROM\s+\S+:latest\b/gim, sev: 'low' },
  { cat: 'Config', name: 'Docker: laeuft als root (USER root)', re: /^\s*USER\s+root\b/gim, sev: 'low' },
  { cat: 'Secrets', name: 'Docker: Secret in ENV/ARG', re: /^\s*(?:ENV|ARG)\s+\w*(?:PASSWORD|SECRET|TOKEN|APIKEY|API_KEY)\w*\s*[= ]\s*\S+/gim, sev: 'medium' },
  { cat: 'Injection', name: 'Pipe nach Shell (curl|bash)', re: /\b(?:curl|wget)\b[^\n|]*\|\s*(?:sudo\s+)?(?:ba)?sh\b/g, sev: 'medium' },
  // Kubernetes
  { cat: 'Config', name: 'Container: privileged', re: /privileged\s*:\s*true/g, sev: 'high' },
  { cat: 'Config', name: 'K8s: Privilege Escalation erlaubt', re: /allowPrivilegeEscalation\s*:\s*true/g, sev: 'medium' },
  { cat: 'Config', name: 'K8s: Host-Namespace (hostNetwork/PID/IPC)', re: /host(?:Network|PID|IPC)\s*:\s*true/g, sev: 'medium' },
  { cat: 'Config', name: 'K8s: laeuft als root (runAsNonRoot:false/runAsUser:0)', re: /runAsNonRoot\s*:\s*false|runAsUser\s*:\s*0\b/g, sev: 'medium' },
  { cat: 'AccessControl', name: 'K8s: cluster-admin-Bindung', re: /\bcluster-admin\b/g, sev: 'high' },
  { cat: 'Config', name: 'K8s: gefaehrliche Capabilities', re: /-\s*(?:SYS_ADMIN|NET_ADMIN|ALL)\b/g, sev: 'medium' },
  { cat: 'Config', name: 'Container-Image :latest', re: /image\s*:\s*\S+:latest\b/g, sev: 'low' },
  // Terraform / Cloud
  { cat: 'AccessControl', name: 'Offen fuers Internet (0.0.0.0/0)', re: /0\.0\.0\.0\/0/g, sev: 'medium' },
  { cat: 'AccessControl', name: 'Bucket oeffentlich (public-read)', re: /\bpublic-read(?:-write)?\b/g, sev: 'high' },
  { cat: 'AccessControl', name: 'DB oeffentlich erreichbar (publicly_accessible)', re: /publicly_accessible\s*=\s*true/g, sev: 'high' },
  { cat: 'Crypto', name: 'Verschluesselung deaktiviert (encrypted=false)', re: /(?:storage_)?encrypted\s*=\s*false/g, sev: 'medium' },
  // CI / GitHub Actions
  { cat: 'Config', name: 'GitHub Actions: pull_request_target', re: /pull_request_target/g, sev: 'medium' },
  { cat: 'Injection', name: 'GitHub Actions: untrusted github.event im Ausdruck', re: /\$\{\{\s*github\.event\.(?:issue|pull_request|comment|review|head_commit)/g, sev: 'medium' },
  { cat: 'AccessControl', name: 'GitHub Actions: permissions write-all', re: /permissions\s*:\s*write-all/g, sev: 'medium' },
];
// Weitere Musterregeln aus rules/*.yml|json (Zod-geprueft); kind: finding erzeugt eigene Befunde
const RULE_FILES = require('./rulefiles').loadRuleFiles();
PATTERN_RULES.push(...RULE_FILES.patterns);
const FILE_FINDING_RULES = RULE_FILES.findings;

// --- Fehlalarm-Filter fuer Secret-Treffer --------------------------------
// Gemessen an echten Projekten: die meisten Treffer waren Platzhalter, Beispielwerte aus Doku/Tests,
// Vorlagen-Variablen (${VAR}), Pruef-Regexe oder Header ohne Schluessel.
const TEST_OR_DOC = /(^|[\\/])(test|tests|__tests__|spec|specs|e2e|fixtures?|mocks?|examples?|samples?|demo|docs?)([\\/]|$)|\.(test|spec)\.[cm]?[jt]sx?$|_test\.(py|go|rb)$|(^|[\\/])test_[^\\/]+\.py$|\.(md|mdx|rst|adoc|txt)$/i;
const PLACEHOLDER_VALUE = /^(?:\*+|x+|\.+|…|<[^>]*>|\{\{[^}]*\}\}|\$\{[^}]*\}|\$\w+|%\w*%?|:\w+|null|none|undefined|true|false|password\d*|passwort|pass|pwd|secret|token|changeme|change[_-]?me|your[_-].*|my[_-]?(password|secret|token|key).*|example.*|sample.*|dummy.*|test.*|fake.*|placeholder.*|redacted|todo|tbd|foo|bar|baz|admin|user(name)?|root|guest|demo.*|some.*|insert.*|enter.*|replace.*|aaa+|123+456?7?8?9?0?|1234567890|qwerty|abc123|letmein|hunter2|peanuts|richtig-pferd-batterie)$/i;
const ENV_REF = /process\.env|os\.environ|getenv|ENV\[|System\.getenv|import\.meta\.env|\$\{\{?\s*(secrets|vars|env)\.|Deno\.env|config\.get|settings\./i;
const EXAMPLE_HOST = /@(?:[\w-]+\.)*(?:example\.(?:com|org|net)|[\w-]+\.(?:example|test|invalid|localhost)|localhost|127\.0\.0\.1|\[::1\]|host|your[\w-]*)(?:[:/]|$)/i;
// Bekannte, oeffentliche Beispielwerte aus Doku (AWS, jwt.io, Stripe-Doku)
const KNOWN_SAMPLES = /AKIAIOSFODNN7EXAMPLE|wJalrXUtnFEMI\/K7MDENG\/bPxRfiCYEXAMPLEKEY|eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ|SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c|sk_live_4eC39[H]qLyjWDarjtT1zdp7dc|EXAMPLE/;

const GENERIC_RULES = new Set(['Generisches Passwort/Secret im Klartext', 'DB Connection String mit Passwort', 'Zugangsdaten in URL', 'JWT', 'Hartkodierter Basic-Auth-Header']);

function lineAt(content, index) {
  const s = content.lastIndexOf('\n', index - 1) + 1;
  const e = content.indexOf('\n', index);
  return content.slice(s, e < 0 ? content.length : e);
}

// true = Treffer ist mit hoher Wahrscheinlichkeit kein echtes Geheimnis
function secretNoise(rule, value, content, index) {
  const line = lineAt(content, index);
  if (KNOWN_SAMPLES.test(value)) return true;
  // Pruef-Code: der Wert steht in einem regulaeren Ausdruck oder einem Vergleich, nicht als Zuweisung
  if (/\bassert\.?(match|throws|equal)|\.test\(|\.match\(|new RegExp|re\.(search|match|compile)|expect\(|toMatch|toContain|includes\(/.test(line) && !/[:=]\s*["'`]/.test(line.replace(/expect\([^)]*\)/, ''))) return true;
  switch (rule.name) {
    case 'Private Key Block': {
      // echter Schluessel: nach der Kopfzeile folgt Base64-Inhalt (auch mit \n im String)
      const after = content.slice(index + value.length, index + value.length + 200).replace(/\\n|\\r|\r|\n|["'+\s,]/g, '');
      return !/^[A-Za-z0-9+/=]{40,}/.test(after);
    }
    case 'Generisches Passwort/Secret im Klartext': {
      const v = (value.match(/[=:]\s*['"]([^'"\n]*)['"]/) || [])[1] || '';
      if (PLACEHOLDER_VALUE.test(v.trim()) || ENV_REF.test(line) || /^\s*(\/\/|#|\*|--|<!--)/.test(line)) return true;
      if (/^[A-Z][A-Z0-9_]{3,}$/.test(v) || (/^[a-z]+(?:[_-][a-z]+)*$/.test(v) && v.length < 12)) return true; // Name einer Variable / Feld
      if (/\s/.test(v) && /^[\p{L} ,.'!?-]+$/u.test(v)) return true; // Satz (Label, Fehlermeldung)
      if (/^(?:https?:)?\/\/|^\/|\.\w{2,4}$|^[\w-]+\/[\w-]/.test(v)) return true;                             // Pfad, Adresse, Dateiname
      return false;
    }
    case 'DB Connection String mit Passwort':
    case 'Zugangsdaten in URL': {
      const cred = (value.match(/:\/\/([^:@/\s]+):([^@\s]*)@/) || []);
      const user = cred[1] || '', pw = cred[2] || '';
      if (/\$\{|\{\{|%\(|<|…|\*{2,}|^\$/.test(pw) || PLACEHOLDER_VALUE.test(pw) || pw === user) return true;
      if (/^(user(name)?|u|a|x|nobody|anonymous)$/i.test(user) && pw.length <= 8) return true;
      if (EXAMPLE_HOST.test(content.slice(index, index + value.length + 60))) return true;
      return false;
    }
    case 'JWT':
      return /^eyJhbGciOiJub25lIi/.test(value); // alg "none": Testmaterial, kein Zugang
    case 'Hartkodierter Basic-Auth-Header':
      return /Basic\s+(?:dXNlcjpwYXNz|dXNlcm5hbWU6cGFzc3dvcmQ|YWRtaW46YWRtaW4|Og==)/.test(value) || ENV_REF.test(line);
    default:
      return false;
  }
}

function lineOf(content, index) {
  let line = 1;
  for (let i = 0; i < index && i < content.length; i++) if (content[i] === '\n') line++;
  return line;
}

function redact(s) {
  if (s.length <= 10) return s[0] + '***';
  return s.slice(0, 4) + '…' + s.slice(-4);
}

// --- Dependency-Manifeste ----------------------------------------------
// Liefert strukturierte Eintraege: { ecosystem, name, version, raw }
// ecosystem passt zu den OSV.dev-Namen (npm, PyPI, Go, Maven, crates.io, RubyGems).

// Konkrete Version aus einem Range/Spezifizierer ziehen (best effort).
function stripVersion(v) {
  if (!v) return '';
  const m = String(v).match(/\d+(?:\.\d+){0,3}(?:[-+][0-9A-Za-z.-]+)?/);
  return m ? m[0] : '';
}

function parseDepsStructured(label, content) {
  const out = [];
  const base = label.split(/[\\/]/).pop().toLowerCase();
  const push = (ecosystem, name, version, raw) => {
    if (name) out.push({ ecosystem, name: name.trim(), version: stripVersion(version), raw: (raw || `${name}@${version}`).trim() });
  };
  try {
    if (base === 'package.json') {
      const j = JSON.parse(content);
      for (const sec of ['dependencies', 'devDependencies', 'optionalDependencies']) {
        for (const [n, v] of Object.entries(j[sec] || {})) push('npm', n, v, `${n}@${v}`);
      }
    } else if (base === 'requirements.txt') {
      content.split(/\r?\n/).forEach((l) => {
        l = l.split('#')[0].trim();
        if (!l || l.startsWith('-')) return;
        const m = l.match(/^([A-Za-z0-9._-]+)\s*(?:\[[^\]]*\])?\s*(?:==|>=|<=|~=|!=|>|<|===)?\s*([\w.*+!-]*)/);
        if (m) push('PyPI', m[1], m[2], l);
      });
    } else if (base === 'pipfile' || base === 'pyproject.toml') {
      (content.match(/^[A-Za-z0-9._-]+\s*=\s*["'][^"']+["']/gm) || []).forEach((l) => {
        const m = l.match(/^([A-Za-z0-9._-]+)\s*=\s*["']([^"']+)["']/);
        if (m) push('PyPI', m[1], m[2], l.trim());
      });
    } else if (base === 'go.mod') {
      (content.match(/[\w.\-/]+\s+v[0-9][\w.\-+]*/g) || []).forEach((l) => {
        const m = l.trim().match(/^([\w.\-/]+)\s+v([0-9][\w.\-+]*)/);
        if (m) push('Go', m[1], m[2], l.trim());
      });
    } else if (base === 'pom.xml') {
      const blocks = content.match(/<dependency>[\s\S]*?<\/dependency>/g) || [];
      blocks.forEach((b) => {
        const g = (b.match(/<groupId>([^<]+)<\/groupId>/) || [])[1];
        const a = (b.match(/<artifactId>([^<]+)<\/artifactId>/) || [])[1];
        const v = (b.match(/<version>([^<]+)<\/version>/) || [])[1];
        if (g && a) push('Maven', `${g}:${a}`, v || '', `${g}:${a}:${v || '?'}`);
      });
    } else if (base === 'build.gradle' || base === 'build.gradle.kts') {
      (content.match(/['"]([\w.\-]+):([\w.\-]+):([\w.\-]+)['"]/g) || []).forEach((l) => {
        const m = l.match(/['"]([\w.\-]+):([\w.\-]+):([\w.\-]+)['"]/);
        if (m) push('Maven', `${m[1]}:${m[2]}`, m[3], `${m[1]}:${m[2]}:${m[3]}`);
      });
    } else if (base === 'cargo.toml') {
      (content.match(/^[A-Za-z0-9_-]+\s*=\s*(?:["'][^"']+["']|\{[^}]*\})/gm) || []).forEach((l) => {
        const name = l.split('=')[0].trim();
        const ver = (l.match(/version\s*=\s*["']([^"']+)["']/) || l.match(/=\s*["']([^"']+)["']/) || [])[1];
        if (name && ver && !['version', 'features', 'default-features'].includes(name)) push('crates.io', name, ver, l.trim());
      });
    } else if (base === 'gemfile' || base === 'gemfile.lock') {
      (content.match(/gem\s+['"][\w.\-]+['"]\s*,\s*['"][^'"]+['"]/g) || []).forEach((l) => {
        const m = l.match(/gem\s+['"]([\w.\-]+)['"]\s*,\s*['"]([^'"]+)['"]/);
        if (m) push('RubyGems', m[1], m[2], l.trim());
      });
    }
  } catch { /* defekte Manifeste ignorieren */ }
  return out;
}

// Eigene Secret-Muster des Nutzers sicher kompilieren (ungueltige Regex -> uebersprungen).
function compileCustom(list) {
  const out = [];
  for (const c of list || []) {
    if (!c || !c.regex) continue;
    try {
      out.push({
        name: c.name || 'Eigene Regel',
        re: new RegExp(c.regex, 'g'),
        sev: ['critical', 'high', 'medium', 'low', 'info'].includes(c.severity) ? c.severity : 'medium',
        custom: true,
      });
    } catch { /* ungueltige Regex ignorieren */ }
  }
  return out;
}

// opts: { customSecrets:[{name,regex,severity}], disabledRules:[name] } - alles optional.
function prescan(units, opts = {}) {
  const findings = [];
  const deps = new Map(); // key -> {ecosystem,name,version,raw}
  const patternHits = {}; // name -> count

  const disabled = new Set(opts.disabledRules || []);
  const secretRules = [...SECRET_RULES.filter((r) => !disabled.has(r.name)), ...compileCustom(opts.customSecrets)];
  const patternRules = PATTERN_RULES.filter((r) => !disabled.has(r.name));

  for (const u of units) {
    const content = u.content || '';
    const devFile = TEST_OR_DOC.test(String(u.label || ''));
    // Secrets -> direkte Befunde
    for (const rule of secretRules) {
      rule.re.lastIndex = 0;
      let m;
      let hits = 0;
      while ((m = rule.re.exec(content)) && hits < 20) {
        if (!rule.custom && secretNoise(rule, m[0], content, m.index)) continue;
        // Tests/Doku: bekannte Formate (AWS, GitHub …) bleiben, generische Muster sind dort fast immer Testwerte
        if (devFile && !rule.custom && GENERIC_RULES.has(rule.name)) continue;
        hits++;
        findings.push(normalizeFinding({
          ruleId: (rule.custom ? 'custom-' : 'secret-') + rule.name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, ''),
          evidence: redactSecret(m[0]),
          title: rule.custom ? `Eigene Regel: ${rule.name}` : `Zugangsdaten im Klartext: ${rule.name}`,
          // In Tests, Beispielen und Doku sind es fast immer Testwerte: sichtbar lassen, aber nicht hoch einstufen
          ...(devFile && !rule.custom ? { devOnly: true } : {}),
          severity: devFile && !rule.custom && rule.sev !== 'info' ? 'low' : rule.sev,
          category: 'Secrets',
          location: `${u.label}:${lineOf(content, m.index)}`,
          description: `Im Code steht ein Wert im Format „${rule.name}“: \`${redact(m[0])}\`. Fest eingetragene Zugangsdaten kann jeder lesen, der den Code, das Programm oder ein Archiv davon bekommt.`,
          reachability: 'Direkt lesbar, sobald jemand die Datei oder den Build in die Hände bekommt (Repository, Download, entpacktes Paket).',
          impact: 'Wer den Code sieht, kann den Zugang benutzen – und von dort aus oft weitere Systeme erreichen oder Daten abziehen.',
          remediation: 'Den Schlüssel sofort beim Anbieter sperren und neu erzeugen. Dann aus dem Code entfernen und über eine Umgebungsvariable oder einen Secret-Manager laden; war er schon in Git, auch die Historie bereinigen.',
          patch: 'Beispiel:\n- const key = "…";\n+ const key = process.env.SERVICE_KEY;  // aus .env / Secret-Manager',
          confidence: 'medium',
        }, 'prescan'));
      }
    }
    // Riskante Muster -> gezaehlt, als Fakten
    for (const rule of patternRules) {
      rule.re.lastIndex = 0;
      let m;
      while ((m = rule.re.exec(content))) {
        const key = `${rule.cat}:${rule.name}`;
        patternHits[key] = patternHits[key] || { cat: rule.cat, name: rule.name, sev: rule.sev, examples: [] };
        if (patternHits[key].examples.length < 8) {
          patternHits[key].examples.push(`${u.label}:${lineOf(content, m.index)}`);
        }
        if (rule.re.lastIndex === m.index) rule.re.lastIndex++;
      }
    }
    // Regeldateien mit kind: finding -> direkte Befunde
    for (const rule of FILE_FINDING_RULES) {
      if (disabled.has(rule.name)) continue;
      rule.re.lastIndex = 0;
      let m, hits = 0;
      while ((m = rule.re.exec(content)) && hits < 5) {
        if (rule.re.lastIndex === m.index) rule.re.lastIndex++;
        hits++;
        findings.push(normalizeFinding({
          ruleId: rule.id || 'rule-' + rule.name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, ''),
          title: `Eigene Regel: ${rule.name}`,
          severity: rule.sev,
          category: rule.cat,
          location: `${u.label}:${lineOf(content, m.index)}`,
          description: rule.description || `Treffer der Regel „${rule.name}“ aus rules/${rule.file}.`,
          remediation: rule.remediation || 'Fundstelle prüfen und nach der Beschreibung der Regel beheben.',
          evidence: m[0].replace(/\s+/g, ' ').slice(0, 160),
          confidence: 'medium',
        }, 'prescan'));
      }
    }
    // Methode: hohe Entropie -> moegliches Secret ohne bekanntes Muster
    for (const h of devFile ? [] : findHighEntropy(content, { label: u.label, kind: u.kind })) {
      findings.push(normalizeFinding({
        ruleId: 'moeglicher-geheimer-schluessel-hohe-entropie', // fester Schluessel, damit der Verlauf erhalten bleibt
        title: 'Möglicher geheimer Schlüssel (hohe Entropie)',
        ...(devFile ? { devOnly: true } : {}),
        severity: h.context && !devFile ? 'medium' : 'low',
        category: 'Secrets',
        location: `${u.label}:${h.line}`,
        description: `Eine sehr zufällig wirkende Zeichenkette (Entropie ${h.entropy}): \`${redact(h.value)}\`. So sehen Schlüssel und Tokens aus.`,
        reachability: 'Direkt lesbar im Code.',
        impact: 'Falls es ein echter Schlüssel ist, kann ihn jeder benutzen, der den Code sieht.',
        remediation: 'Prüfen, ob es ein echter Schlüssel ist. Falls ja: beim Anbieter sperren, neu erzeugen und über eine Umgebungsvariable laden.',
        confidence: 'low',
      }, 'prescan'));
    }

    // Dependencies
    for (const d of parseDepsStructured(u.label, content)) {
      deps.set(`${d.ecosystem}:${d.name}@${d.version}`, d);
    }
  }
  // Methode: sensible Dateien/Metadaten (name-/endungsbasiert)
  findings.push(...fsaudit(units));
  const depList = [...deps.values()];

  // Fakten-Text fuer den KI-Prompt
  const factLines = [];
  if (depList.length) {
    factLines.push('Erkannte Abhaengigkeiten (bitte auf bekannte CVEs/veraltete Versionen pruefen):');
    depList.slice(0, 200).forEach((d) => factLines.push(`  - [${d.ecosystem}] ${d.raw}`));
  }
  const hitKeys = Object.keys(patternHits);
  if (hitKeys.length) {
    factLines.push('', 'Statisch erkannte riskante Muster (Heuristik, bitte verifizieren):');
    for (const k of hitKeys) {
      const h = patternHits[k];
      factLines.push(`  - [${h.sev}] ${h.cat} / ${h.name} bei: ${h.examples.join(', ')}`);
    }
  }

  return {
    findings,
    facts: factLines.join('\n'),
    deps: depList,
    patternSummary: patternHits,
  };
}

// Namen aller eingebauten Regeln (fuer die „deaktivieren"-Auswahl in der UI).
function ruleNames() {
  return { secrets: SECRET_RULES.map((r) => r.name), patterns: [...PATTERN_RULES, ...FILE_FINDING_RULES].map((r) => ({ cat: r.cat, name: r.name })) };
}

module.exports = { prescan, ruleNames, SECRET_RULES, PATTERN_RULES, FILE_FINDING_RULES, ruleFileErrors: RULE_FILES.errors };
