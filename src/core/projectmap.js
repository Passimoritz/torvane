'use strict';

// Projektkarte fuer die KI: ein kurzer Ueberblick, den jeder Analyse-Durchgang mitbekommt, damit die KI
// einzelne Dateiausschnitte im Zusammenhang sieht (wo sind die Einstiege, welche Routen haben eine
// Anmeldung, welche Datenbank, welche Geheimnisse kommen aus der Umgebung).
// Rein statisch, schnell, hoechstens ~2500 Zeichen.

const { routesOf } = require('./modules/appsec');

const base = (u) => String(u.label || '').replace(/\\/g, '/');
const MAX = 2500;

const DB = [
  ['Prisma', /@prisma\/client|prisma\./], ['Sequelize', /sequelize/i], ['TypeORM', /typeorm/], ['Mongoose/MongoDB', /mongoose|mongodb/],
  ['Knex', /\bknex\b/], ['PostgreSQL (pg)', /require\(['"]pg['"]\)|from ['"]pg['"]|psycopg/], ['MySQL', /mysql2?|pymysql|mysqlclient/],
  ['SQLite', /sqlite3?|better-sqlite3/], ['Redis', /\bredis\b|ioredis/], ['SQLAlchemy', /sqlalchemy/], ['Django ORM', /django\.db|models\.Model/],
  ['JDBC/JPA', /java\.sql|javax\.persistence|jakarta\.persistence/], ['Entity Framework', /DbContext/],
];
const FRAMEWORK = [
  ['Express', /require\(['"]express['"]\)|from ['"]express['"]/], ['Fastify', /fastify/], ['Koa', /require\(['"]koa['"]\)/], ['NestJS', /@nestjs\//],
  ['Next.js', /from ['"]next\//], ['Flask', /from flask import|import flask/], ['FastAPI', /from fastapi import/], ['Django', /from django/],
  ['Spring', /org\.springframework/], ['Laravel', /Illuminate\\/], ['Rails', /ActionController|Rails\.application/], ['ASP.NET', /Microsoft\.AspNetCore/],
  ['Electron', /require\(['"]electron['"]\)|from ['"]electron['"]/], ['Bukkit/Paper-Plugin', /org\.bukkit|io\.papermc/],
];
const AUTH = [['JWT', /jsonwebtoken|jwt\.(sign|verify|decode)|PyJWT|jose/], ['Passport', /passport/], ['Sitzungs-Cookie', /express-session|cookie-session|SESSION_ENGINE|flask_login/],
  ['OAuth/OIDC', /oauth|openid|oidc/i], ['bcrypt/argon2', /bcrypt|argon2/], ['API-Schlüssel im Header', /x-api-key|apiKey\s*===|api_key\s*==/i]];

function buildProjectMap(units) {
  const code = (units || []).filter((u) => typeof u.content === 'string' && u.kind !== 'binary-strings' && !u.vendored && !u.generated);
  if (!code.length) return '';
  const all = code.map((u) => u.content).join('\n');
  const found = (list) => list.filter(([, re]) => re.test(all)).map(([n]) => n);
  const lines = [];
  const fw = found(FRAMEWORK); if (fw.length) lines.push(`Frameworks: ${fw.join(', ')}`);
  const db = found(DB); if (db.length) lines.push(`Datenhaltung: ${db.join(', ')}`);
  const au = found(AUTH); if (au.length) lines.push(`Anmeldung/Krypto: ${au.join(', ')}`);
  // Routen mit Anmelde-Status
  const routes = [];
  for (const u of code) for (const r of routesOf(u)) routes.push({ file: base(u), ...r, global: !!routesOf(u).global });
  if (routes.length) {
    const open = routes.filter((r) => !r.auth && !r.global);
    lines.push(`Routen: ${routes.length} (davon ${routes.length - open.length} mit erkennbarer Anmeldung)`);
    for (const r of routes.slice(0, 40)) lines.push(`  ${r.method.toUpperCase()} ${r.path}  [${r.auth || r.global ? 'Anmeldung' : 'ohne erkennbare Anmeldung'}]  ${r.file}`);
  }
  // Einstiegspunkte
  const entries = code.filter((u) => /\.listen\(\s*(process\.env\.PORT|\d{2,5})|app\.run\(|uvicorn\.run|createServer\(|new BrowserWindow|extends JavaPlugin|public static void main\(/.test(u.content)).map(base);
  if (entries.length) lines.push(`Einstiegspunkte: ${entries.slice(0, 8).join(', ')}`);
  // Konfiguration aus der Umgebung (nur Namen, keine Werte)
  const env = new Set();
  for (const m of all.matchAll(/process\.env\.([A-Z][A-Z0-9_]{2,})|os\.environ(?:\.get)?\(\s*['"]([A-Z][A-Z0-9_]{2,})|getenv\(\s*['"]([A-Z][A-Z0-9_]{2,})/g)) env.add(m[1] || m[2] || m[3]);
  if (env.size) lines.push(`Umgebungsvariablen: ${[...env].slice(0, 30).join(', ')}`);
  // Aufrufe nach aussen
  const out = found([['fetch/axios (HTTP-Abrufe)', /\bfetch\(|axios\.|got\(|requests\.(get|post)|httpx\./], ['Systembefehle', /child_process|subprocess|ProcessBuilder|os\.system/], ['Dateisystem-Schreibzugriffe', /writeFile|fs\.promises\.write|open\([^)]*['"]w/], ['Templates/HTML', /render_template|res\.render|innerHTML|dangerouslySetInnerHTML/]]);
  if (out.length) lines.push(`Riskante Fähigkeiten im Code: ${out.join(', ')}`);
  const text = lines.join('\n');
  return text.length > MAX ? text.slice(0, MAX) + '\n  …' : text;
}

module.exports = { buildProjectMap };
