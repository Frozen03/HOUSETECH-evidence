require("dotenv").config();
const express = require("express");
const cors = require("cors");
const fs = require("fs");
const path = require("path");
const jwt = require("jsonwebtoken");
const { OAuth2Client } = require("google-auth-library");
const crypto = require("crypto");

const app = express();

/* ------------ Config ------------ */
const PORT = process.env.PORT || 8787;
const JWT_SECRET = process.env.JWT_SECRET || "dev-secret";
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || "";
const CORS_ORIGIN = process.env.CORS_ORIGIN || "*";

// Render disk je /data; lokalno uporabimo ../data
const DATA_DIR =
  process.env.DATA_DIR ||
  (fs.existsSync("/data") ? "/data" : path.join(__dirname, "..", "data"));
const USERS_PATH = path.join(DATA_DIR, "users.json");
const PROJECTS_PATH = path.join(DATA_DIR, "projects.json");
const MATERIALS_PATH = path.join(DATA_DIR, "materials.json");

// Frontend
const WEB_DIR = path.join(__dirname, "..", "web");

/* ------------ Middleware ------------ */
app.use(
  cors({
    origin: CORS_ORIGIN === "*" ? true : CORS_ORIGIN.split(",").map(s => s.trim()),
    credentials: true,
  })
);
app.use(express.json({ limit: "1mb" }));

/* ------------ Init data dir & files ------------ */
fs.mkdirSync(DATA_DIR, { recursive: true });
for (const p of [USERS_PATH, PROJECTS_PATH, MATERIALS_PATH]) {
  if (!fs.existsSync(p)) fs.writeFileSync(p, JSON.stringify(p.includes("users") ? {} : []));
}

/* ------------ Utils ------------ */
const readJson = (p, fallback) => {
  try { return JSON.parse(fs.readFileSync(p, "utf8")); } catch { return fallback; }
};
const writeJson = (p, data) => fs.writeFileSync(p, JSON.stringify(data, null, 2));

let users = readJson(USERS_PATH, {});
let projects = readJson(PROJECTS_PATH, []);
let materials = readJson(MATERIALS_PATH, []);

const saveUsers = () => writeJson(USERS_PATH, users);
const saveProjects = () => writeJson(PROJECTS_PATH, projects);
const saveMaterials = () => writeJson(MATERIALS_PATH, materials);

const googleClient = GOOGLE_CLIENT_ID ? new OAuth2Client(GOOGLE_CLIENT_ID) : null;

const signJWT = (user) =>
  jwt.sign({ sub: user.email, roles: user.roles || [] }, JWT_SECRET, { expiresIn: "7d" });

function authRequired(req, res, next) {
  const hdr = req.headers.authorization || "";
  const token = hdr.startsWith("Bearer ") ? hdr.slice(7) : null;
  if (!token) return res.status(401).json({ error: "Manjka žeton" });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = { email: payload.sub, roles: payload.roles || [] };
    next();
  } catch {
    return res.status(401).json({ error: "Neveljaven žeton" });
  }
}
const requireRole = (allowed) => (req, res, next) =>
  (req.user?.roles || []).some(r => allowed.includes(r)) ? next() : res.status(403).json({ error: "Ni dovoljenja" });

/* ------------ Auth ------------ */
app.post("/auth/google/verify", async (req, res) => {
  try {
    const { credential } = req.body || {};
    if (!credential || !googleClient || !GOOGLE_CLIENT_ID) {
      return res.status(400).json({ error: "Manjka GOOGLE_CLIENT_ID ali credential" });
    }

    const ticket = await googleClient.verifyIdToken({
      idToken: credential,
      audience: GOOGLE_CLIENT_ID,
    });
    const payload = ticket.getPayload();
    const email = payload?.email?.toLowerCase();
    if (!email) return res.status(400).json({ error: "Ni emaila v Google tokenu" });

    // whitelist
    const u = users[email];
    if (!u) return res.status(403).json({ error: "Uporabnik ni dodan. Obrni se na administratorja." });

    const userOut = { email, name: u.name || email, roles: u.roles || [] };
    const accessToken = signJWT(userOut);
    return res.json({ access_token: accessToken, user: userOut });
  } catch (e) {
    console.error("Google verify error:", e.message);
    return res.status(401).json({ error: "Neuspešna verifikacija" });
  }
});

/* ------------ Users ------------ */
app.get("/users", authRequired, (req, res) => res.json(users));

app.post("/users", authRequired, requireRole(["Owner", "CEO"]), (req, res) => {
  const { email, name } = req.body || {};
  const key = String(email || "").toLowerCase().trim();
  if (!key || !name) return res.status(400).json({ error: "email in name sta obvezna" });
  if (!users[key]) users[key] = { name, roles: [] };
  saveUsers();
  res.status(201).json({ email: key, ...users[key] });
});

app.patch("/users/:email", authRequired, requireRole(["Owner", "CEO"]), (req, res) => {
  const email = decodeURIComponent(req.params.email).toLowerCase();
  if (!users[email]) return res.status(404).json({ error: "Uporabnik ne obstaja" });
  const { name, roles } = req.body || {};
  if (typeof name === "string") users[email].name = name;
  if (Array.isArray(roles)) users[email].roles = roles;
  saveUsers();
  res.json({ email, ...users[email] });
});

app.delete("/users/:email", authRequired, requireRole(["Owner", "CEO"]), (req, res) => {
  const email = decodeURIComponent(req.params.email).toLowerCase();
  if (!users[email]) return res.status(404).json({ error: "Ni uporabnika" });
  if ((users[email].roles || []).includes("Owner")) {
    return res.status(403).json({ error: "Ownerja ni dovoljeno izbrisati." });
  }
  delete users[email];
  saveUsers();
  res.status(204).end();
});

/* ------------ Projects ------------ */
app.get("/projects", authRequired, (req, res) => res.json(projects));

app.post("/projects", authRequired, requireRole(["Owner", "CEO"]), (req, res) => {
  const { name } = req.body || {};
  if (!String(name || "").trim()) return res.status(400).json({ error: "Manjka name" });
  const proj = { id: crypto.randomUUID(), name: String(name).trim() };
  projects.push(proj);
  saveProjects();
  res.status(201).json(proj);
});

app.delete("/projects/:id", authRequired, requireRole(["Owner", "CEO"]), (req, res) => {
  const id = req.params.id;
  const before = projects.length;
  projects = projects.filter((p) => p.id !== id);
  if (projects.length === before) return res.status(404).json({ error: "Ni projekta" });
  saveProjects();
  res.status(204).end();
});

/* ------------ Materials ------------ */
app.get("/materials", authRequired, (req, res) => res.json(materials));

app.post("/materials", authRequired, (req, res) => {
  const name = String(req.body?.name || "").trim();
  const uom = String(req.body?.uom || "kos").trim();
  if (!name) return res.status(400).json({ error: "Manjka 'name'." });

  const existing = materials.find(
    (m) => m.name.trim().toLowerCase() === name.toLowerCase()
  );
  if (existing) {
    existing.uom = uom || existing.uom;
    saveMaterials();
    return res.json(existing);
  }
  const m = { id: crypto.randomUUID(), name, uom };
  materials.push(m);
  saveMaterials();
  res.status(201).json(m);
});

/* ------------ Health (optional) ------------ */
app.get("/healthz", (_req, res) => res.json({ ok: true }));

/* ------------ Serve frontend (web/) ------------ */
app.use(express.static(WEB_DIR, { extensions: ["html"] }));

// Catch-all za SPA, vendar pusti API poti pri miru
app.get("*", (req, res, next) => {
  const p = req.path;
  if (
    p.startsWith("/auth") ||
    p.startsWith("/users") ||
    p.startsWith("/projects") ||
    p.startsWith("/materials") ||
    p.startsWith("/healthz")
  ) return next();
  res.sendFile(path.join(WEB_DIR, "index.html"));
});

/* ------------ Start ------------ */
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
  console.log(`Serving WEB from: ${WEB_DIR}`);
  console.log(`DATA dir: ${DATA_DIR}`);
});
