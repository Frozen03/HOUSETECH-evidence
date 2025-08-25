// POPRAVLJENA VERZIJA server.js – trajno shranjevanje podatkov + normalizacija people na e-maile
require("dotenv").config();
const express = require("express");
const cors = require("cors");
const fs = require("fs");
const path = require("path");
const jwt = require("jsonwebtoken");
const { OAuth2Client } = require("google-auth-library");
const multer = require("multer");
const crypto = require("crypto");

const app = express();

const PORT = process.env.PORT || 8787;
const JWT_SECRET = process.env.JWT_SECRET || "dev-secret";
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const CORS_ORIGIN = process.env.CORS_ORIGIN || "*";

// ====== PERSISTENCA ======
const DATA_DIR = process.env.DATA_DIR || path.resolve(__dirname, "../data");
const WEB_DIR  = process.env.WEB_DIR  || path.resolve(__dirname, "../web");

fs.mkdirSync(DATA_DIR, { recursive: true });
fs.mkdirSync(path.join(DATA_DIR, "uploads"), { recursive: true });

const P = {
  users:      path.join(DATA_DIR, "users.json"),
  projects:   path.join(DATA_DIR, "projects.json"),
  materials:  path.join(DATA_DIR, "materials.json"),
  presence:   path.join(DATA_DIR, "presence.json"),
  jobs:       path.join(DATA_DIR, "jobs.json"),
  workplans:  path.join(DATA_DIR, "workplans")
};
fs.mkdirSync(P.workplans, { recursive: true });

function readJSON(file, fallback) {
  try { return JSON.parse(fs.readFileSync(file, "utf8")); }
  catch { return fallback; }
}
function writeJSON(file, data) {
  fs.writeFileSync(file, JSON.stringify(data, null, 2));
}

let users     = readJSON(P.users, {});
let projects  = readJSON(P.projects, []);
let materials = readJSON(P.materials, []);
let presence  = readJSON(P.presence, []);
let jobs      = readJSON(P.jobs, []);

const saveUsers     = () => writeJSON(P.users, users);
const saveProjects  = () => writeJSON(P.projects, projects);
const saveMaterials = () => writeJSON(P.materials, materials);
const savePresence  = () => writeJSON(P.presence, presence);
const saveJobs      = () => writeJSON(P.jobs, jobs);

// ====== Google OAuth ======
if (!GOOGLE_CLIENT_ID) console.warn("⚠️  GOOGLE_CLIENT_ID manjka – prijava ne bo delovala.");
const googleClient = new OAuth2Client(GOOGLE_CLIENT_ID);

// ====== JWT helperji ======
function signJWT(email, roles) {
  return jwt.sign({ sub: email, roles: roles || [] }, JWT_SECRET, { expiresIn: "7d" });
}
function authRequired(req, res, next) {
  try {
    const hdr = req.headers.authorization || "";
    const token = hdr.startsWith("Bearer ") ? hdr.slice(7) : null;
    if (!token) return res.status(401).json({ error: "Manjka žeton" });
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = { email: payload.sub, roles: payload.roles || [] };
    next();
  } catch (e) {
    return res.status(401).json({ error: "Neveljaven žeton" });
  }
}
function requireRole(rolesAllowed) {
  return (req, res, next) => {
    const roles = req.user?.roles || [];
    if (roles.some(r => rolesAllowed.includes(r))) return next();
    return res.status(403).json({ error: "Ni dovoljenja" });
  };
}
function hasManagerRole(user) {
  const roles = user?.roles || [];
  return roles.includes("Owner") || roles.includes("CEO") || roles.includes("vodja");
}

// ====== Upload ======
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, path.join(DATA_DIR, "uploads")),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname || "").toLowerCase();
    cb(null, crypto.randomUUID() + ext);
  }
});
const upload = multer({ storage, limits: { fileSize: 50 * 1024 * 1024, files: 10 } });

app.use("/uploads", express.static(path.join(DATA_DIR, "uploads")));

// ====== Auth ======
app.post("/auth/google/verify", async (req, res) => {
  try {
    const { credential } = req.body || {};
    if (!credential) return res.status(400).json({ error: "Manjka credential" });

    const ticket = await googleClient.verifyIdToken({ idToken: credential, audience: GOOGLE_CLIENT_ID });
    const payload = ticket.getPayload();
    const email = (payload?.email || "").toLowerCase();

    if (!email) return res.status(400).json({ error: "Ni emaila v Google tokenu" });
    const u = users[email];
    if (!u) return res.status(403).json({ error: "Uporabnik ni dodan. Obrni se na administratorja." });

    const token = signJWT(email, u.roles || []);
    return res.json({
      access_token: token,
      user: { email, name: u.name || email, roles: u.roles || [] }
    });
  } catch (e) {
    console.error("Google verify error:", e.message);
    return res.status(401).json({ error: "Neuspešna verifikacija" });
  }
});

// ====== Helper za normalizacijo imena/emaila ======
function toEmailLike(val) {
  if (!val) return val;
  const s = String(val).trim();
  if (!s) return s;
  if (s.includes("@")) return s.toLowerCase();
  const hit = Object.entries(users).find(([,u]) => (u?.name || "").toLowerCase() === s.toLowerCase());
  if (hit) return hit[0].toLowerCase();
  return s;
}

// ====== Workplan (mesečni plan) ======
app.get("/workplan/month", authRequired, (req, res) => {
  try {
    const { start } = req.query;
    if (!start) return res.status(400).json({ error: "Manjka parameter start" });

    const yearMonth = String(start).slice(0, 7);
    const planFile = path.join(P.workplans, `plan-${yearMonth}.json`);

    if (fs.existsSync(planFile)) {
      const raw = JSON.parse(fs.readFileSync(planFile, "utf8"));
      if (raw && raw.days) {
        for (const dayKey of Object.keys(raw.days)) {
          raw.days[dayKey] = (raw.days[dayKey] || []).map(it => ({
            ...it,
            people: Array.isArray(it.people) ? it.people.map(toEmailLike) : []
          }));
        }
      }
      return res.json(raw);
    }
    return res.json({ days: {} });
  } catch (e) {
    console.error("GET /workplan/month error:", e);
    res.status(500).json({ error: "Napaka pri branju plana" });
  }
});

app.put("/workplan/month", authRequired, (req, res) => {
  try {
    const { start, days } = req.body || {};
    if (!start || typeof days !== "object") return res.status(400).json({ error: "Manjka parameter start ali days" });

    const yearMonth = String(start).slice(0, 7);
    const planFile = path.join(P.workplans, `plan-${yearMonth}.json`);

    const current = fs.existsSync(planFile) ? JSON.parse(fs.readFileSync(planFile, "utf8")) : { days: {} };
    if (!current.days) current.days = {};

    const isManager = hasManagerRole(req.user);
    if (isManager) {
      const normalized = { days: {} };
      for (const dayKey of Object.keys(days)) {
        const arr = Array.isArray(days[dayKey]) ? days[dayKey] : [];
        normalized.days[dayKey] = arr.map(it => ({
          ...it,
          people: Array.isArray(it.people) ? it.people.map(toEmailLike) : []
        }));
      }
      fs.writeFileSync(planFile, JSON.stringify(normalized, null, 2));
      return res.json({ success: true, mode: "replace" });
    }

    // zaposleni: update samo statusa
    const email = req.user.email.toLowerCase();
    const merged = { days: { ...current.days } };
    for (const dayKey of Object.keys(days || {})) {
      const incomingArr = Array.isArray(days[dayKey]) ? days[dayKey] : [];
      const existingArr = Array.isArray(merged.days[dayKey]) ? merged.days[dayKey] : [];
      const max = Math.min(incomingArr.length, existingArr.length);
      for (let i = 0; i < max; i++) {
        const inc = incomingArr[i] || {};
        const ex  = existingArr[i] || {};
        ex.people = Array.isArray(ex.people) ? ex.people.map(toEmailLike) : [];
        if (ex.people.includes(email)) {
          const incStatuses = inc.statuses || {};
          if (Object.prototype.hasOwnProperty.call(incStatuses, email)) {
            ex.statuses = ex.statuses || {};
            ex.statuses[email] = incStatuses[email];
            existingArr[i] = ex;
          }
        }
      }
      merged.days[dayKey] = existingArr;
    }
    fs.writeFileSync(planFile, JSON.stringify(merged, null, 2));
    return res.json({ success: true, mode: "merge-status" });
  } catch (e) {
    console.error("PUT /workplan/month error:", e);
    res.status(500).json({ error: "Napaka pri shranjevanju plana" });
  }
});

// ====== statika ======
app.use("/", express.static(WEB_DIR, { index: "index.html" }));
app.get("/", (req, res) => res.sendFile(path.join(WEB_DIR, "index.html")));

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
  console.log(`Serving WEB from: ${WEB_DIR}`);
  console.log(`DATA dir: ${DATA_DIR}`);
});
