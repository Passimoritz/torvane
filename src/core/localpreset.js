'use strict';

// Voreinstellungen fuer lokale Modelle (Ollama): Ollama nimmt ohne Angabe nur ein kleines Kontextfenster
// (je nach Version 2048-4096 Tokens) und schneidet laengere Eingaben stillschweigend ab. Hier wird die
// Kontextlaenge passend zur Eingabe gesetzt und durch die Modellgroesse begrenzt; kleine Modelle bekommen
// kleinere Bloecke, damit sie nicht ueberfordert werden.

// Groesse in Milliarden Parametern aus dem Modellnamen ("qwen2.5-coder:14b", "llama3.1:8b-instruct", "phi3:mini")
function modelSizeB(name) {
  const n = String(name || '').toLowerCase();
  const m = n.match(/(?:^|[:\-_ ])(\d+(?:\.\d+)?)\s*b(?:\b|-)/) || n.match(/(\d+(?:\.\d+)?)b\b/);
  if (m) return Number(m[1]);
  if (/mini|tiny|small/.test(n)) return 3;
  return 0; // unbekannt
}

// Obergrenze des Kontextfensters je Modellgroesse (Speicherbedarf waechst mit dem Kontext)
function maxCtxFor(sizeB) {
  if (!sizeB) return 16384;
  if (sizeB <= 4) return 8192;
  if (sizeB <= 9) return 16384;
  return 32768;
}

// Optionen fuer /api/chat: num_ctx passend zur Eingabe (Zeichen/3.5 ~ Tokens) plus Antwort, auf 2048 gerundet
function ollamaOptions({ model, promptChars = 0, maxTokens = 4096, numCtx } = {}) {
  if (numCtx) return { num_ctx: Number(numCtx), num_predict: maxTokens };
  const need = Math.ceil(promptChars / 3.5) + (maxTokens || 4096) + 256;
  const ctx = Math.min(maxCtxFor(modelSizeB(model)), Math.max(4096, Math.ceil(need / 2048) * 2048));
  return { num_ctx: ctx, num_predict: maxTokens || 4096 };
}

// Blockgroesse (Zeichen Quelltext je KI-Aufruf) fuer lokale Modelle; null = Standard der Analyse
function charBudgetFor(config = {}) {
  if (config.provider !== 'ollama') return null;
  const s = modelSizeB(config.model);
  if (!s) return 24000;
  if (s <= 4) return 12000;
  if (s <= 9) return 24000;
  if (s <= 15) return 36000;
  return null;
}

module.exports = { modelSizeB, maxCtxFor, ollamaOptions, charBudgetFor };
