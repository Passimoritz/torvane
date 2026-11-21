'use strict';

// Anzeigename der App an EINER Stelle. Fuer eine Umbenennung nur NAME aendern:
// - Elemente mit data-brand="name" / data-brand="tagline" bekommen den Text,
// - Seitentitel und alle sichtbaren Texte, in denen "Torvane" steht, werden ersetzt,
// - die englische Uebersetzung (i18n.js) schlaegt weiter mit "Torvane" nach und setzt danach den neuen Namen ein.
// Interne Kennungen (window.vigil, Dateinamen, IPC) bleiben bewusst unveraendert.
(() => {
  const NAME = 'Torvane';
  const TAGLINE = 'Sicherheitsprüfung';
  const ORIGINAL = 'Torvane';
  const brand = Object.freeze({ name: NAME, tagline: TAGLINE, original: ORIGINAL });
  window.APP_BRAND = brand;

  const RE = new RegExp(`\\b${ORIGINAL}\\b`, 'g');
  // Text mit dem Originalnamen -> Text mit dem aktuellen Namen (bei gleichem Namen unveraendert)
  window.brandText = (s) => (NAME === ORIGINAL || s == null ? s : String(s).replace(RE, NAME));
  // Umgekehrt fuer Woerterbuch-Nachschlagen: aktueller Name -> Originalname
  const BACK = new RegExp(`\\b${NAME.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`, 'g');
  window.unbrandText = (s) => (NAME === ORIGINAL || s == null ? s : String(s).replace(BACK, ORIGINAL));

  // Native Rueckfragen und Hinweise sind keine DOM-Texte
  for (const fn of ['confirm', 'alert']) {
    const native = window[fn];
    if (native && NAME !== ORIGINAL) window[fn] = (m) => native.call(window, window.brandText(m));
  }

  const ATTRS = ['placeholder', 'title', 'aria-label'];
  const has = (s) => { RE.lastIndex = 0; return RE.test(s); };
  function apply(root) {
    if (!root) return;
    if (root.nodeType === 3) { if (has(root.nodeValue)) root.nodeValue = window.brandText(root.nodeValue); return; }
    if (root.nodeType !== 1) return;
    root.querySelectorAll('[data-brand]').forEach((el) => { el.textContent = el.dataset.brand === 'tagline' ? TAGLINE : NAME; });
    if (NAME === ORIGINAL) return;
    const w = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
    const nodes = [];
    while (w.nextNode()) nodes.push(w.currentNode);
    for (const n of nodes) if (has(n.nodeValue)) n.nodeValue = window.brandText(n.nodeValue);
    for (const el of [root, ...root.querySelectorAll('*')]) for (const a of ATTRS) {
      const v = el.getAttribute(a);
      if (v && has(v)) el.setAttribute(a, window.brandText(v));
    }
  }
  function start() {
    document.title = NAME;
    apply(document.body);
    if (NAME === ORIGINAL) return;
    // Spaeter eingefuegte Inhalte ebenfalls umbenennen
    // Spaeter eingefuegte Knoten, geaenderte Texte und Attribute; jede Ersetzung entfernt den alten Namen, also keine Schleife
    new MutationObserver((muts) => {
      for (const m of muts) {
        if (m.type === 'childList') m.addedNodes.forEach(apply);
        else if (m.type === 'characterData') apply(m.target);
        else { const v = m.target.getAttribute(m.attributeName); if (v && has(v)) m.target.setAttribute(m.attributeName, window.brandText(v)); }
      }
    }).observe(document.body, { childList: true, subtree: true, characterData: true, attributes: true, attributeFilter: ATTRS });
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start); else start();
})();
