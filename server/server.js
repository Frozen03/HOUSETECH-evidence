// server/server.js
require("dotenv").config();

const express = require("express");
const cors = require("cors");
const fs = require("fs");
const path = require("path");
const jwt = require("jsonwebtoken");
const { OAuth2Client } = require("google-auth-library");
const crypto = require("crypto");

// -------------------- Konfiguracija --------------------
const app = express();
const PORT = process.env.PORT || 8787;
const JWT_SECRET = process.env.JWT_SECRET || "dev-secret";
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || "";
const CORS_ORIGIN = process.env.CORS_ORIGIN || "*"; // po potrebi zamenjaj z domeno

// CORS (preveri origin, ali pusti vse)
app.use(cors({ origin: CORS_ORIGIN === "*" ? true : CORS_ORIGIN, credentials: false }));
app.use(express.json({ limit: "1mb" }));

if (!GOOGLE_CLIENT_ID) {
  console.warn("⚠️  GOOGLE_CLIENT_ID manjka v okolju (.env). Google verifikacija ne bo delovala!");
}
const googleClient = new OAuth2Client(GOOGLE_CLIENT_ID);

// -------------------- Data dir (Render /data -> fallback) --------------------
function resolveWritableDir(preferred, fallback) {
  try {
    fs.mkdirSync(preferred, { recursive: true });
    fs.accessSync(preferred, fs.constants.W_OK);
    console.log("Using data dir:", preferred);
    return preferred;
  } catch (e) {
    console.warn(`⚠️  '${preferred}' ni zapisljiv (${e.code}). Uporabljam fallback: '${fallback}'.`);
    fs.mkdirSync(fallback, { recursive: true });
    return fallback;
  }
}

const PREFERRED_DATA = process.env.DATA_DIR || (process.env.RENDER ? "/data" : path.join(__dirname, "data"));
const FALLBACK_DATA  = path.join(__dirname, "data");
const DATA_DIR       = resolveWritableDir(PREFERRED_DATA, FALLBACK_DATA);

// Poti do JSON datotek
const USERS_PATH     = path.join(DATA_DIR, "users.json");
const PROJECTS_PATH  = path.join(DATA_DIR, "projects.json");
const MATERIALS_PATH = path.join(DATA_DIR, "materials.json");

// Ustvari prazne datoteke, če manjkajo
function ensureFile(p, emptyValue) {
  if (!fs.existsSync(p)) {
    fs.writeFileSync(p, JSON.stringify(emptyValue, null, 2));
  }
}
ensureFile(USERS_PATH, {});
ensureFile(PROJECTS_PATH, []);
ensureFile(MATERIALS_PATH, []);

// Loader/saver helperji
const readJson  = (p, fallback) => { try { return JSON.parse(fs.readFileSync(p, "utf8")); } catch { return fallback; } };
const writeJson = (p, data) => fs.writeFileSync(p, JSON.stringify(data, null, 2));

// In-memory cache
let users     = readJson(USERS_PATH, {});
let projects  = readJson(PROJECTS_PATH, []);
let materials = readJson(MATERIALS_PATH, []);

const saveUsers     = () => writeJson(USERS_PATH, users);
const saveProjects  = () => writeJson(PROJECTS_PATH, projects);
const saveMaterials = () => writeJson(MATERIALS_PATH, materials);

// -------------------- JWT & avtorizacija --------------------
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

function requireRole(roleArr) {
  return (req, res, next) => {
    const roles = req.user?.roles || [];
    if (roles.some((r) => roleArr.includes(r))) return next();
    return res.status(403).json({ error: "Ni dovoljenja" });
  };
}

// -------------------- Auth: Google Sign-In verify --------------------
app.post("/auth/google/verify", async (req, res) => {
  try {
    const { credential } = req.body || {};
    if (!credential) return res.status(400).json({ error: "Manjka credential" });

    const ticket = await googleClient.verifyIdToken({
      idToken: credential,
      audience: GOOGLE_CLIENT_ID,
    });
    const payload = ticket.getPayload();
    const email = payload?.email?.toLowerCase();
    if (!email) return res.status(400).json({ error: "Ni emaila v Google tokenu" });

    // Strežniški whitelist – če ni v users.json: zavrni
    const u = users[email];
    if (!u) {
      return res.status(403).json({ error: "Uporabnik ni dodan. Obrni se na administratorja." });
    }

    const userOut = { email, name: u.name || email, roles: u.roles || [] };
    const accessToken = signJWT({ email, roles: userOut.roles });
    return res.json({ access_token: accessToken, user: userOut });
  } catch (e) {
    console.error("Google verify error:", e?.message || e);
    return res.status(401).json({ error: "Neuspešna verifikacija" });
  }
});

// -------------------- USERS (Owner/CEO) --------------------
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

// -------------------- PROJECTS --------------------
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

// -------------------- MATERIALS --------------------
// GET: vsi materiali za autocomplete
app.get("/materials", authRequired, (req, res) => res.json(materials));

// POST: upsert po imenu (idempotentno)
app.post("/materials", authRequired, (req, res) => {
  const name = String(req.body?.name || "").trim();
  const uom = String(req.body?.uom || "kos").trim();
  if (!name) return res.status(400).json({ error: "Manjka 'name'." });

  const existing = materials.find((m) => m.name.trim().toLowerCase() === name.toLowerCase());
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

// -------------------- Health & Root --------------------
app.get("/", (_req, res) => res.type("text/plain").send("HOUSETECH Ops API is live"));
app.get("/healthz", (_req, res) => res.json({ ok: true }));

// -------------------- Start --------------------
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
  console.log(`Data dir: ${DATA_DIR}`);
});
