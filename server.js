const http = require('node:http');
const fs = require('node:fs');
const fsp = require('node:fs/promises');
const path = require('node:path');
const crypto = require('node:crypto');
const { URL } = require('node:url');

const PORT = Number(process.env.PORT || 3000);
const HOST = process.env.HOST || '127.0.0.1';
const ROOT = __dirname;
const DATA_DIR = path.join(ROOT, 'data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const ROUNDS_FILE = path.join(DATA_DIR, 'rounds.json');
const HTML_FILE = path.join(ROOT, 'rps-gesture.html');

const sessions = new Map();

async function ensureDataFiles() {
  await fsp.mkdir(DATA_DIR, { recursive: true });
  await ensureJsonFile(USERS_FILE, []);
  await ensureJsonFile(ROUNDS_FILE, []);
}

async function ensureJsonFile(filePath, fallback) {
  try {
    await fsp.access(filePath, fs.constants.F_OK);
  } catch {
    await fsp.writeFile(filePath, JSON.stringify(fallback, null, 2));
  }
}

async function readJson(filePath, fallback) {
  try {
    const raw = await fsp.readFile(filePath, 'utf8');
    return JSON.parse(raw);
  } catch {
    return fallback;
  }
}

async function writeJson(filePath, value) {
  await fsp.writeFile(filePath, JSON.stringify(value, null, 2));
}

function normalizeUsername(username) {
  return username.trim().toLowerCase();
}

function titleizeUsername(username) {
  return username.trim().toUpperCase();
}

function json(res, statusCode, payload) {
  res.writeHead(statusCode, { 'Content-Type': 'application/json; charset=utf-8' });
  res.end(JSON.stringify(payload));
}

function sendHtml(res, html) {
  res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
  res.end(html);
}

function notFound(res) {
  json(res, 404, { error: 'Not found' });
}

function methodNotAllowed(res) {
  json(res, 405, { error: 'Method not allowed' });
}

async function readBody(req) {
  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);
  const raw = Buffer.concat(chunks).toString('utf8');
  if (!raw) return {};
  try {
    return JSON.parse(raw);
  } catch {
    throw new Error('Invalid JSON body');
  }
}

async function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
  const derivedKey = await new Promise((resolve, reject) => {
    crypto.scrypt(password, salt, 64, (error, key) => {
      if (error) reject(error);
      else resolve(key.toString('hex'));
    });
  });
  return `${salt}:${derivedKey}`;
}

async function verifyPassword(password, storedHash) {
  const [salt, expected] = String(storedHash).split(':');
  if (!salt || !expected) return false;
  const computed = await hashPassword(password, salt);
  return crypto.timingSafeEqual(Buffer.from(computed), Buffer.from(`${salt}:${expected}`));
}

function makeToken() {
  return crypto.randomBytes(24).toString('hex');
}

function getToken(req) {
  const auth = req.headers.authorization || '';
  if (!auth.startsWith('Bearer ')) return '';
  return auth.slice('Bearer '.length).trim();
}

function getSessionUser(req) {
  const token = getToken(req);
  if (!token) return null;
  return sessions.get(token) || null;
}

function computeStats(rounds, usernameKey) {
  const ownedRounds = rounds.filter(round => round.usernameKey === usernameKey);
  const stats = { wins: 0, losses: 0, draws: 0, totalRounds: ownedRounds.length };
  for (const round of ownedRounds) {
    if (round.result === 'win') stats.wins++;
    else if (round.result === 'loss') stats.losses++;
    else stats.draws++;
  }
  return stats;
}

async function handleLogin(req, res) {
  if (req.method !== 'POST') return methodNotAllowed(res);
  const body = await readBody(req);
  const username = String(body.username || '').trim();
  const password = String(body.password || '');

  if (!username) return json(res, 400, { error: 'Username is required' });
  if (username.length < 2 || username.length > 16) return json(res, 400, { error: 'Username must be 2-16 characters' });
  if (!/^[a-zA-Z0-9 _-]+$/.test(username)) return json(res, 400, { error: 'Username contains unsupported characters' });
  if (password.length < 6) return json(res, 400, { error: 'Password must be at least 6 characters' });

  const usernameKey = normalizeUsername(username);
  const users = await readJson(USERS_FILE, []);
  const existingUser = users.find(user => user.usernameKey === usernameKey);
  let created = false;

  if (!existingUser) {
    const passwordHash = await hashPassword(password);
    users.push({
      usernameKey,
      displayName: titleizeUsername(username),
      passwordHash,
      createdAt: new Date().toISOString()
    });
    await writeJson(USERS_FILE, users);
    created = true;
  } else {
    const passwordOk = await verifyPassword(password, existingUser.passwordHash);
    if (!passwordOk) return json(res, 401, { error: 'Incorrect password' });
  }

  const user = users.find(entry => entry.usernameKey === usernameKey) || {
    usernameKey,
    displayName: titleizeUsername(username)
  };
  const token = makeToken();
  sessions.set(token, { usernameKey: user.usernameKey, displayName: user.displayName });

  json(res, 200, {
    created,
    token,
    player: {
      usernameKey: user.usernameKey,
      displayName: user.displayName
    }
  });
}

async function handleSession(req, res) {
  if (req.method !== 'GET') return methodNotAllowed(res);
  const session = getSessionUser(req);
  if (!session) return json(res, 401, { error: 'Session expired' });
  json(res, 200, { player: session });
}

async function handleStats(req, res) {
  if (req.method !== 'GET') return methodNotAllowed(res);
  const session = getSessionUser(req);
  if (!session) return json(res, 401, { error: 'Unauthorized' });
  const rounds = await readJson(ROUNDS_FILE, []);
  json(res, 200, { stats: computeStats(rounds, session.usernameKey) });
}

async function handleRoundCreate(req, res) {
  if (req.method !== 'POST') return methodNotAllowed(res);
  const session = getSessionUser(req);
  if (!session) return json(res, 401, { error: 'Unauthorized' });

  const body = await readBody(req);
  const roundNumber = Number(body.roundNumber);
  const playerGesture = body.playerGesture === null ? null : String(body.playerGesture || '');
  const cpuGesture = String(body.cpuGesture || '');
  const result = String(body.result || '');

  if (!Number.isFinite(roundNumber) || roundNumber < 1) return json(res, 400, { error: 'Invalid round number' });
  if (playerGesture !== null && !['rock', 'paper', 'scissors'].includes(playerGesture)) return json(res, 400, { error: 'Invalid player gesture' });
  if (!['rock', 'paper', 'scissors'].includes(cpuGesture)) return json(res, 400, { error: 'Invalid CPU gesture' });
  if (!['win', 'loss', 'draw'].includes(result)) return json(res, 400, { error: 'Invalid result' });

  const rounds = await readJson(ROUNDS_FILE, []);
  rounds.push({
    id: crypto.randomUUID(),
    usernameKey: session.usernameKey,
    displayName: session.displayName,
    roundNumber,
    playerGesture,
    cpuGesture,
    result,
    createdAt: new Date().toISOString()
  });
  await writeJson(ROUNDS_FILE, rounds);

  json(res, 201, {
    ok: true,
    stats: computeStats(rounds, session.usernameKey)
  });
}

async function handleHealth(req, res) {
  if (req.method !== 'GET') return methodNotAllowed(res);
  json(res, 200, { ok: true, uptime: process.uptime() });
}

async function handleRequest(req, res) {
  const url = new URL(req.url, `http://${req.headers.host || `${HOST}:${PORT}`}`);

  if (url.pathname === '/' || url.pathname === '/rps-gesture.html') {
    const html = await fsp.readFile(HTML_FILE, 'utf8');
    return sendHtml(res, html);
  }
  if (url.pathname === '/api/health') return handleHealth(req, res);
  if (url.pathname === '/api/auth/login') return handleLogin(req, res);
  if (url.pathname === '/api/session') return handleSession(req, res);
  if (url.pathname === '/api/stats/me') return handleStats(req, res);
  if (url.pathname === '/api/rounds') return handleRoundCreate(req, res);
  return notFound(res);
}

async function start() {
  await ensureDataFiles();
  const server = http.createServer((req, res) => {
    handleRequest(req, res).catch(error => {
      console.error(error);
      json(res, 500, { error: 'Internal server error' });
    });
  });

  server.listen(PORT, HOST, () => {
    console.log(`HANDOFF server running at http://${HOST}:${PORT}`);
  });
}

start().catch(error => {
  console.error(error);
  process.exitCode = 1;
});
