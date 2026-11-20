'use strict';

// Code-Maske: ein kleiner Tokenizer, der Kommentare, Zeichenketten und (in JS) Regex-Literale erkennt.
// maskCode() liefert einen gleich langen Text, in dem Kommentare (und auf Wunsch Zeichenketten) durch
// Leerzeichen ersetzt sind - Zeilen und Positionen bleiben erhalten. Regeln, die auf Aufrufe zielen,
// treffen so nicht mehr auf Text in Kommentaren oder Doku-Strings.
// Kein vollstaendiger Parser, aber robust gegen die haeufigen Faelle: Block- und Zeilenkommentare,
// verschachtelte Template-Literale mit ${…}, Python-Triple-Strings, Escapes.

const FAMILY = [
  [/\.(m?[jt]sx?|cjs|vue|svelte)$/i, 'js'],
  [/\.py$/i, 'py'],
  [/\.(java|kt|kts|scala|groovy|gradle|cs|go|rs|swift|dart|c|cc|cpp|cxx|h|hpp|m|mm)$/i, 'c'],
  [/\.php$/i, 'php'],
  [/\.(rb|sh|bash|zsh|ps1|ya?ml|toml|tf|conf|ini|properties|dockerfile)$|(^|\/)Dockerfile$/i, 'hash'],
];
const familyOf = (label) => (FAMILY.find(([re]) => re.test(String(label || ''))) || [null, null])[1];

// Gibt { comments: Uint8Array, strings: Uint8Array } zurueck (1 = Zeichen gehoert dazu)
function scan(text, fam) {
  const n = text.length;
  const com = new Uint8Array(n);
  const str = new Uint8Array(n);
  const rx = new Uint8Array(n);
  if (!fam) return { comments: com, strings: str, regex: rx };
  const lineCom = fam === 'py' || fam === 'hash' ? ['#'] : fam === 'php' ? ['//', '#'] : ['//'];
  const blockCom = fam === 'py' || fam === 'hash' ? null : ['/*', '*/'];
  let i = 0;
  const stack = []; // offene Template-Literale (JS): Klammertiefe je ${
  let lastSig = ''; // letztes bedeutsames Zeichen (fuer Regex-Erkennung)
  const mark = (arr, a, b) => { for (let k = a; k < b && k < n; k++) arr[k] = 1; };
  while (i < n) {
    const c = text[i];
    const two = text.substr(i, 2);
    // Ende eines ${ … } im Template
    if (stack.length && c === '}' && stack[stack.length - 1] === 0) { stack.pop(); i++; i = readTemplate(i); lastSig = '`'; continue; }
    if (stack.length && c === '{') stack[stack.length - 1]++;
    if (stack.length && c === '}') stack[stack.length - 1]--;
    // Kommentare
    if (lineCom.some((t) => text.startsWith(t, i)) && !(fam === 'hash' && c === '#' && text[i + 1] === '{')) {
      const e = text.indexOf('\n', i); const end = e < 0 ? n : e; mark(com, i, end); i = end; continue;
    }
    if (blockCom && two === blockCom[0]) {
      const e = text.indexOf(blockCom[1], i + 2); const end = e < 0 ? n : e + 2; mark(com, i, end); i = end; continue;
    }
    // Zeichenketten
    if (fam === 'py' && (text.startsWith('"""', i) || text.startsWith("'''", i))) {
      const q = text.substr(i, 3); const e = text.indexOf(q, i + 3); const end = e < 0 ? n : e + 3;
      mark(str, i + 3, end - 3); i = end; lastSig = 'x'; continue;
    }
    if (c === '"' || c === "'" || (c === '`' && (fam === 'js' || fam === 'c'))) {
      if (c === '`' && fam === 'js') { i = readTemplate(i + 1); lastSig = '`'; continue; }
      let j = i + 1;
      while (j < n && text[j] !== c && text[j] !== '\n') { if (text[j] === '\\') j++; j++; }
      mark(str, i + 1, j); i = j + 1; lastSig = 'x'; continue;
    }
    // Regex-Literal (JS): "/" nach einem Operator oder am Zeilenanfang
    if (fam === 'js' && c === '/' && /^[(,=:[!&|?{};+\-*%<>~^]?$/.test(lastSig) && text[i + 1] !== '/' && text[i + 1] !== '*') {
      let j = i + 1, cls = false;
      while (j < n && text[j] !== '\n') {
        if (text[j] === '\\') { j += 2; continue; }
        if (text[j] === '[') cls = true; else if (text[j] === ']') cls = false; else if (text[j] === '/' && !cls) break;
        j++;
      }
      if (j < n && text[j] === '/') { mark(str, i + 1, j); mark(rx, i + 1, j); i = j + 1; while (i < n && /[a-z]/i.test(text[i])) i++; lastSig = 'x'; continue; }
    }
    if (!/\s/.test(c)) lastSig = /[\w$)\].]/.test(c) ? 'x' : c;
    i++;
  }
  return { comments: com, strings: str, regex: rx };

  // liest ab i (nach dem oeffnenden `) bis zum schliessenden ` oder bis ${ (dann Code)
  function readTemplate(start) {
    let j = start;
    while (j < n) {
      if (text[j] === '\\') { str[j] = 1; if (j + 1 < n) str[j + 1] = 1; j += 2; continue; }
      if (text[j] === '`') return j + 1;
      if (text[j] === '$' && text[j + 1] === '{') { stack.push(0); return j + 2; }
      str[j] = 1; j++;
    }
    return n;
  }
}

const cache = new WeakMap();
function scanUnit(u) {
  if (!u || typeof u.content !== 'string') return null;
  let s = cache.get(u);
  if (!s) { s = scan(u.content, familyOf(u.label || u.path)); cache.set(u, s); }
  return s;
}

// Liegt die Position im Kommentar (bzw. mit strings=true auch in einer Zeichenkette)?
function inComment(u, idx) { const s = scanUnit(u); return !!(s && idx >= 0 && s.comments[idx]); }
function inString(u, idx) { const s = scanUnit(u); return !!(s && idx >= 0 && s.strings[idx]); }

// Optionen: strings (alle Zeichenketten), regex (nur Regex-Literale) zusaetzlich zu Kommentaren ausblenden
function maskCode(text, label, { strings = false, regex = false } = {}) {
  const s = scan(text, familyOf(label));
  let out = '';
  for (let i = 0; i < text.length; i++) out += (s.comments[i] || (strings && s.strings[i]) || (regex && s.regex[i])) && text[i] !== '\n' ? ' ' : text[i];
  return out;
}
function inRegex(u, idx) { const s = scanUnit(u); return !!(s && idx >= 0 && s.regex[idx]); }

module.exports = { maskCode, inComment, inString, inRegex, familyOf, scan };
