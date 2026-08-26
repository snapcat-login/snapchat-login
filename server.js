// server.js — Deploy this on Render.com (free tier)
//
// Setup locally first:
//   npm init -y
//   npm install express bcrypt cors
//   node server.js
//
// Then deploy to Render.com — see instructions below.

const express = require('express');
const bcrypt  = require('bcrypt');
const cors    = require('cors');
const fs      = require('fs');
const path    = require('path');

const app  = express();
const PORT = process.env.PORT || 3000;
const DB   = path.join(__dirname, 'users.json');

// ── CORS ────────────────────────────────────────────────────────────
// Frontend and backend are served from the same origin now, so CORS
// restrictions aren't really needed — but we keep the middleware in
// place (fully open) in case you ever call this API from elsewhere.
app.use(cors());

app.use(express.json());

// ── Serve the frontend HTML/CSS/JS files from this same server ────────
app.use(express.static(__dirname));

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// ── DB helpers ───────────────────────────────────────────────────────
function loadUsers() {
  if (!fs.existsSync(DB)) return [];
  try { return JSON.parse(fs.readFileSync(DB, 'utf8')); }
  catch { return []; }
}

function saveUsers(users) {
  fs.writeFileSync(DB, JSON.stringify(users, null, 2));
}

function findUser(email) {
  return loadUsers().find(u => u.email.toLowerCase() === email.toLowerCase());
}

// ── Routes ───────────────────────────────────────────────────────────

// POST /api/login
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password)
    return res.status(400).json({ error: 'Email and password are required.' });
});

// POST /api/register  (use this to create users)
app.post('/api/register', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password)
    return res.status(400).json({ error: 'Email and password are required.' });

  if (password.length < 8)
    return res.status(400).json({ error: 'Password must be at least 8 characters.' });

  if (findUser(email))
    return res.status(409).json({ error: 'An account with that email already exists.' });

  const passwordHash = await bcrypt.hash(password, 12);
  const users = loadUsers();
  users.push({ id: Date.now().toString(), email: email.toLowerCase().trim(), passwordHash, createdAt: new Date().toISOString() });
  saveUsers(users);

  return res.status(201).json({ message: 'Account created.' });
});

// GET /admin/users  — view stored users (no passwords exposed)
// ⚠️  Protect this before going fully public (add a secret key check, etc.)
app.get('/admin/users', (req, res) => {
  const users = loadUsers().map(({ id, email, createdAt }) => ({ id, email, createdAt }));
  res.json({ count: users.length, users });
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
