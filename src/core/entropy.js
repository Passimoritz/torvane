'use strict';

// Methode: hohe Shannon-Entropie deutet auf geheime Schluessel/Token hin,
// die kein bekanntes Secret-Muster treffen (zufaellig aussehende Zeichenketten).
// Bewusst konservativ. Gemessen an echten Projekten (Node-Pakete, Java, TS, SQL, Shell) waren
// fast alle alten Treffer Bezeichner, Pfade, Adressen, UUIDs, oeffentliche Schluessel oder
// Klassendateien - die Filter unten schliessen genau diese Gruppen aus.

function shannon(s) {
  const freq = Object.create(null);
  for (const ch of s) freq[ch] = (freq[ch] || 0) + 1;
  let H = 0;
  const n = s.length;
  for (const k in freq) { const p = freq[k] / n; H -= p * Math.log2(p); }
  return H;
}

const SECRETISH = /(key|secret|token|passw|pwd|auth|cred|api|private|signature|bearer|access)/i;
// Name links vom Wert: password = "…", "apiKey": '…', TOKEN=…, Authorization: Bearer …
const ASSIGN_CTX = /(?:key|secret|token|passw\w*|pwd|auth\w*|cred\w*|api\w*|private\w*|signature|bearer|access\w*)\w*["'\]]?\s*(?:[:=]|=>|:=)\s*(?:b?["'`]|Bearer\s+|Basic\s+)?$|\b(?:Bearer|Basic)\s+$/i;
const TOKEN = /[A-Za-z0-9+/_=\-]{24,}/g;
// Zeilen, die eher Hashes/Assets/Integritaet/oeffentliche Schluessel enthalten -> ueberspringen.
const SKIP_LINE = /base64|data:image|integrity=|"integrity"|sha(?:1|256|384|512)|checksum|digest|fingerprint|[a-f0-9]{40,}|\.(png|jpe?g|gif|svg|webp|woff2?|ttf|ico)\b|BEGIN (?:PUBLIC KEY|CERTIFICATE|PGP PUBLIC)|ssh-(?:rsa|ed25519) |ecdsa-sha2-/i;
// Dateien, in denen hohe Entropie normal und harmlos ist
const SKIP_FILE = /(^|[\\/])(package-lock\.json|npm-shrinkwrap\.json|yarn\.lock|pnpm-lock\.ya?ml|bun\.lockb?|composer\.lock|Cargo\.lock|Gemfile\.lock|poetry\.lock|Pipfile\.lock|uv\.lock|go\.sum|packages\.lock\.json|gradle\.lockfile)$|\.(pub|asc|crt|cer|sig|map|svg|snap)$|\.min\.(js|css)$|\.pub\.pem$|[\\/]known_hosts$/i;
const PLACEHOLDER = /example|sample|dummy|placeholder|changeme|your[_-]|xxxx|0000000|1234567|abcdef|fake|lorem|redacted|\*{3}/i;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

// Besteht der Wert aus Woertern (camelCase, snake_case, kebab-case, Pfadsegmente)? Dann ist es ein Name, kein Schluessel.
function wordLike(tok) {
  const parts = tok.split(/[_\-./+=$]+|(?<=[a-z])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])|(?<=[A-Za-z])(?=\d)|(?<=\d)(?=[A-Za-z])/).filter(Boolean);
  if (parts.length < 2) return false;
  const letters = parts.filter((p) => /^[A-Za-z]+$/.test(p));
  if (!letters.length) return false;
  const tiny = parts.filter((p) => p.length <= 2).length;
  const avg = letters.reduce((s, p) => s + p.length, 0) / letters.length;
  const vowelOk = letters.filter((p) => p.length >= 4).every((p) => /[aeiouy]/i.test(p));
  return avg >= 3.5 && tiny / parts.length <= 0.3 && vowelOk;
}

// Pfad aus Woertern, IDs und Hashes (C:/Users/…/a68dcff4-8f8f-…/scratchpad): jedes Segment kurz, Wort, UUID oder Hex
function pathLike(tok) {
  const segs = tok.split('/').filter(Boolean);
  if (segs.length < 3 || /[+=]/.test(tok)) return false;
  return segs.every((s) => s.length <= 12 || wordLike(s) || /^[0-9a-f-]+$/i.test(s) || /^[\w.-]+$/.test(s) && /[-_.]/.test(s) && s.split(/[-_.]/).every((p) => p.length <= 12));
}

// Base64, das zu lesbarem Text dekodiert, ist kodierter Text (Testdaten, Beispiele), kein Schluessel.
function base64Text(tok) {
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(tok) || tok.length % 4) return false;
  const s = Buffer.from(tok, 'base64').toString('latin1');
  const printable = s.replace(/[^\x20-\x7e\n\r\t]/g, '').length / Math.max(1, s.length);
  return printable > 0.95 && /[a-z]{3,}/i.test(s);
}

// Liegt der Treffer in einer Webadresse ohne Schluessel-Parameter?
function inPlainUrl(line, start, end) {
  const re = /\b[a-z][a-z0-9+.-]*:\/\/[^\s"'`<>)\]]+/gi; let m;
  while ((m = re.exec(line))) {
    if (start >= m.index && end <= m.index + m[0].length) return !/[?&#](?:api_?key|key|token|access_token|secret|sig|signature|auth|password)=/i.test(m[0]);
  }
  return false;
}

// opts: { label, kind } - Binaerdaten (extrahierte Strings) und Lockfiles werden nicht geprueft
function findHighEntropy(content, opts = {}) {
  const hits = [];
  if (opts.kind === 'binary-strings' || (opts.label && SKIP_FILE.test(opts.label))) return hits;
  const lines = String(content || '').split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line.length > 400 || SKIP_LINE.test(line)) continue;
    TOKEN.lastIndex = 0;
    let m;
    while ((m = TOKEN.exec(line))) {
      const tok = m[0];
      if (/^[0-9]+$/.test(tok) || /^[a-f0-9]+$/i.test(tok) || UUID.test(tok)) continue; // Zahlen, Hex (Hashes), UUIDs
      if (/(.)\1{5,}/.test(tok) || PLACEHOLDER.test(tok)) continue;                  // Platzhalter, Wiederholungen
      if (wordLike(tok) || base64Text(tok) || pathLike(tok)) continue;              // Namen, Pfade, kodierter Text
      if (inPlainUrl(line, m.index, m.index + tok.length)) continue;                // Doku-/Paket-Adressen
      const before = line.slice(0, m.index);
      const contextSecret = ASSIGN_CTX.test(before);
      const H = shannon(tok);
      const mixed = /[A-Z]/.test(tok) && /[a-z]/.test(tok) && /[0-9]/.test(tok);
      const quoted = /["'`]\s*$/.test(before) || /[:=]\s*$/.test(before);
      const strong = H >= 4.3 && tok.length >= 40 && mixed && quoted;
      if ((contextSecret && H >= 3.6 && (mixed || H >= 4.2)) || strong) {
        hits.push({ value: tok, line: i + 1, entropy: Math.round(H * 100) / 100, context: contextSecret });
        if (hits.length >= 40) return hits;
      }
    }
  }
  return hits;
}

module.exports = { shannon, findHighEntropy, wordLike, base64Text };
