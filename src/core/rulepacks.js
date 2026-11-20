'use strict';

// Signierte Regelpakete zum Nachladen (z. B. fuer Laravel, Spring, Minecraft):
//   { "format": "torvane-rulepack/1", "name": "spring-extra", "version": "1.0.0", "description": "…",
//     "rules": [ … wie in rules/*.yml … ], "signature": { "alg": "ed25519", "keyId": "…", "sig": "base64" } }
// Geladen wird ein Paket nur, wenn die Signatur zu einem vertrauenswuerdigen Schluessel passt
// (rules/trusted-keys/*.pem im Programm oder ~/.torvane/trusted-keys/*.pem). Ein veraendertes oder
// fremd signiertes Paket wird abgelehnt und als Hinweis gemeldet.

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { canonical, keyIdOf, generateKeyPair } = require('./signing');

const HOME = process.env.TORVANE_HOME || path.join(os.homedir(), '.torvane');
const PACK_DIR = path.join(HOME, 'rulepacks');
const TRUST_DIRS = [path.join(__dirname, '..', '..', 'rules', 'trusted-keys'), path.join(HOME, 'trusted-keys')];
const FORMAT = 'torvane-rulepack/1';

const body = (pack) => { const { signature, ...rest } = pack || {}; return Buffer.from(canonical(rest), 'utf8'); };

function signPack(pack, privateKeyPem, publicKeyPem) {
  const p = { ...pack, format: FORMAT };
  delete p.signature;
  const sig = crypto.sign(null, body(p), crypto.createPrivateKey(privateKeyPem)).toString('base64');
  return { ...p, signature: { alg: 'ed25519', keyId: keyIdOf(publicKeyPem), sig } };
}

function trustedKeys(dirs = TRUST_DIRS) {
  const out = [];
  for (const d of dirs) {
    let files = [];
    try { files = fs.readdirSync(d).filter((f) => /\.pem$/i.test(f)); } catch { continue; }
    for (const f of files) { try { const pem = fs.readFileSync(path.join(d, f), 'utf8'); out.push({ pem, keyId: keyIdOf(pem), file: f }); } catch { /* unlesbar */ } }
  }
  return out;
}

// { ok, keyId, error }
function verifyPack(pack, keys = trustedKeys()) {
  if (!pack || pack.format !== FORMAT) return { ok: false, error: 'kein Torvane-Regelpaket' };
  if (!/^[a-z0-9][a-z0-9._-]{1,60}$/i.test(String(pack.name || ''))) return { ok: false, error: 'ungültiger Paketname' };
  const s = pack.signature || {};
  if (s.alg !== 'ed25519' || !s.sig || !s.keyId) return { ok: false, error: 'nicht signiert' };
  const key = keys.find((k) => k.keyId === s.keyId);
  if (!key) return { ok: false, keyId: s.keyId, error: `Schlüssel ${String(s.keyId).slice(0, 12)}… ist nicht vertrauenswürdig` };
  let ok = false;
  try { ok = crypto.verify(null, body(pack), crypto.createPublicKey(key.pem), Buffer.from(s.sig, 'base64')); } catch { ok = false; }
  return ok ? { ok: true, keyId: s.keyId } : { ok: false, keyId: s.keyId, error: 'Signatur passt nicht (Paket verändert?)' };
}

// Alle installierten Pakete pruefen; nur gueltige werden als Regel-Dokumente geliefert
function loadTrustedPacks(dir = PACK_DIR, keys) {
  const docs = [], notes = [];
  let files = [];
  try { files = fs.readdirSync(dir).filter((f) => /\.json$/i.test(f)).sort(); } catch { return { docs, notes }; }
  const k = keys || trustedKeys();
  for (const f of files) {
    let pack;
    try { pack = JSON.parse(fs.readFileSync(path.join(dir, f), 'utf8')); } catch { notes.push(`Regelpaket ${f}: nicht lesbar`); continue; }
    const v = verifyPack(pack, k);
    if (!v.ok) { notes.push(`Regelpaket ${f} nicht geladen: ${v.error}`); continue; }
    docs.push({ doc: { rules: pack.rules || [] }, label: `${pack.name}@${pack.version || '0'}` });
  }
  return { docs, notes };
}

async function readSource(src) {
  if (/^https:\/\//i.test(src)) { const r = await fetch(src); if (!r.ok) throw new Error(`Download fehlgeschlagen (${r.status})`); return r.text(); }
  if (/^http:\/\//i.test(src)) throw new Error('Nur https-Adressen.');
  return fs.readFileSync(src, 'utf8');
}

// Paket pruefen und nach ~/.torvane/rulepacks/<name>.json legen
async function installPack(src, { dir = PACK_DIR, keys } = {}) {
  const pack = JSON.parse(await readSource(src));
  const v = verifyPack(pack, keys || trustedKeys());
  if (!v.ok) return { ok: false, error: v.error };
  fs.mkdirSync(dir, { recursive: true });
  const file = path.join(dir, `${pack.name}.json`);
  fs.writeFileSync(file, JSON.stringify(pack, null, 2));
  return { ok: true, file, name: pack.name, version: pack.version, rules: (pack.rules || []).length, keyId: v.keyId };
}

function trustKey(pemFile, dir = TRUST_DIRS[1]) {
  const pem = fs.readFileSync(pemFile, 'utf8');
  crypto.createPublicKey(pem); // nur gueltige oeffentliche Schluessel
  if (/PRIVATE KEY/.test(pem)) throw new Error('Das ist ein privater Schlüssel – bitte nur den öffentlichen Teil eintragen.');
  fs.mkdirSync(dir, { recursive: true });
  const id = keyIdOf(pem);
  fs.writeFileSync(path.join(dir, `${id.slice(0, 16)}.pem`), pem);
  return { keyId: id };
}

module.exports = { signPack, verifyPack, trustedKeys, loadTrustedPacks, installPack, trustKey, generateKeyPair, PACK_DIR, FORMAT };
