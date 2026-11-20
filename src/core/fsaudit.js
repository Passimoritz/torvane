'use strict';

// Methode: sensible Dateien/Metadaten anhand von Name/Endung/Art erkennen -
// unabhaengig vom Inhalt (ergaenzt die inhaltsbasierten Prescan-Regeln).
// Wo der Name allein taeuscht (oeffentliche Schluessel, .env-Vorlagen, Migrationen), entscheidet ein Blick in den Inhalt.

const { normalizeFinding } = require('./schema');

const PUBLIC_KEY = /-----BEGIN (?:PUBLIC KEY|RSA PUBLIC KEY|CERTIFICATE|PGP PUBLIC KEY BLOCK|CERTIFICATE REQUEST|X509 CRL)-----|^ssh-(?:rsa|ed25519|dss) |^ecdsa-sha2-/m;
const PRIVATE_KEY = /-----BEGIN (?:RSA |EC |OPENSSH |PGP |DSA |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----/;
// Datei mit echten Daten (INSERT/COPY-Bloecke in Mengen) statt Schema/Migration
const looksLikeDump = (c) => /^-- (?:MySQL|MariaDB|PostgreSQL)(?: database)? dump|^-- Dump completed|^COPY [\w."]+ \([^)]*\) FROM stdin;/m.test(c) || (c.match(/^\s*INSERT INTO/gim) || []).length >= 50;

const RULES = [
  {
    id: 'fs-private-key-file', re: /(^|[\\/])id_(rsa|dsa|ecdsa|ed25519)$|\.(pem|key|p12|pfx|jks|keystore|ppk)$/i, sev: 'high', cat: 'Secrets', what: 'Privater Schluessel / Zertifikatsdatei',
    // Oeffentliche Schluessel und Zertifikate sind zum Weitergeben da; nur echte private Schluessel (oder unlesbare Container) melden
    skip: (label, c) => /\.pub(\.pem)?$/i.test(label) || (c != null && /\.(pem|key)$/i.test(label) && PUBLIC_KEY.test(c) && !PRIVATE_KEY.test(c)),
  },
  {
    id: 'fs-credentials-file', re: /(^|[\\/])\.env(\.[\w-]+)?$|(^|[\\/])\.netrc$|(^|[\\/])\.pgpass$|(^|[\\/])\.git-credentials$|(^|[\\/])credentials$/i, sev: 'high', cat: 'Secrets', what: 'Zugangsdaten-Datei',
    // Vorlagen (.env.example …) sind gewollt im Repo; nur melden, wenn darin ein echter Wert steht
    skip: (label, c) => /\.env\.(example|sample|template|dist|defaults?|tpl|schema|test|ci)$/i.test(label) && !(c && /^\s*\w*(?:PASSWORD|SECRET|TOKEN|API_?KEY)\w*\s*=\s*['"]?(?![<$]|changeme|your|xxx|\.\.\.|example)[^\s'"#]{12,}/im.test(c)),
  },
  { id: 'fs-npmrc', re: /(^|[\\/])\.npmrc$/i, sev: 'medium', cat: 'Secrets', what: '.npmrc mit Zugangstoken', skip: (label, c) => c != null && !/_authToken\s*=\s*(?!\$\{)\S|_auth\s*=\s*\S|_password\s*=\s*\S/.test(c) },
  { id: 'fs-backup-file', re: /\.(bak|old|orig|save|tmp|swp|swo)$|~$/i, sev: 'low', cat: 'Config', what: 'Backup-/Temp-/Editor-Datei (evtl. sensibler Inhalt)' },
  { id: 'fs-os-metadata', re: /(^|[\\/])\.ds_store$|(^|[\\/])thumbs\.db$/i, sev: 'low', cat: 'Config', what: 'Betriebssystem-Metadaten (Dateinamen-Leak)' },
  { id: 'fs-vcs-metadata', re: /(^|[\\/])\.(git|svn|hg)[\\/]/i, sev: 'medium', cat: 'Config', what: 'Versionsverwaltungs-Metadaten mitgeliefert' },
  {
    id: 'fs-database-dump', re: /\.(sql|dump)$/i, sev: 'low', cat: 'Config', what: 'Datenbank-Dump',
    // Migrationen, Schemata und Seeds sind Quellcode; nur echte Dumps mit Daten melden
    skip: (label, c) => /\.sql$/i.test(label) && (c == null || /(^|[\\/])(migrations?|migrate|schema|ddl|db[\\/]changelog|flyway|liquibase)([\\/]|$)/i.test(label) || !looksLikeDump(c)),
  },
  { id: 'fs-auth-file', re: /\.(kdbx|ovpn|htpasswd)$|(^|[\\/])\.htpasswd$/i, sev: 'medium', cat: 'Secrets', what: 'Passwort-/VPN-/Auth-Datei' },
];

function fsaudit(units) {
  const findings = [];
  const seen = new Set();
  for (const u of units || []) {
    const label = u.label || '';
    const content = typeof u.content === 'string' && u.kind !== 'binary-strings' ? u.content : null;
    for (const r of RULES) {
      if (!r.re.test(label)) continue;
      if (r.skip && r.skip(label, content)) continue;
      const key = r.id + '|' + label;
      if (seen.has(key)) continue;
      seen.add(key);
      findings.push(normalizeFinding({
        ruleId: r.id, // fest, damit Baseline und Ausblenden ueber Dateinamen hinweg funktionieren
        title: `${r.what}: ${label.split(/[\\/]/).pop()}`,
        severity: r.sev,
        category: r.cat,
        location: label,
        description: `Die Datei "${label}" deutet auf ${r.what.toLowerCase()} hin und sollte nicht ungeschuetzt in Code, Build oder Repository liegen.`,
        reachability: 'Lesbar fuer jeden mit Zugriff auf Code, Artefakt oder Repository.',
        impact: r.cat === 'Secrets' ? 'Moeglicher Abfluss von Zugangsdaten/Schluesseln.' : 'Informations-Leak, erleichtert weitere Angriffe.',
        remediation: 'Datei entfernen bzw. aus Auslieferung/Repo ausschliessen (.gitignore/ignore) und betroffene Secrets rotieren.',
        confidence: 'medium',
      }, 'prescan'));
    }
  }
  return findings;
}

module.exports = { fsaudit };
