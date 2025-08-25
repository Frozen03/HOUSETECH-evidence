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

// ----- CORS & body parsers -----
app.use(cors({ origin: CORS_ORIGIN, credentials: false, methods: ["GET","POST","PUT","PATCH","DELETE","OPTIONS"] }));
app.use(express.json({ limit: "20mb" })); // malo višji limit, ker frontend pošilja slike URL-je v jobih

// ----- Poti do podatkov -----
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, "data");
const WEB_DIR  = process.env.WEB_DIR  || path.join(__dirname); // služi index.html iz iste mape kot server.js (po tvoji strukturi)

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

// naloži ob zagonu
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

// ----- Google OAuth -----
if (!GOOGLE_CLIENT_ID) {
  console.warn("⚠️  GOOGLE_CLIENT_ID manjka – prijava ne bo delovala.");
}
const googleClient = new OAuth2Client(GOOGLE_CLIENT_ID);

// ----- JWT helperji -----
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

// ----- Upload (fotografije/video) -----
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, path.join(DATA_DIR, "uploads")),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname || "").toLowerCase();
    cb(null, crypto.randomUUID() + ext);
  }
});
const upload = multer({ storage, limits: { fileSize: 50 * 1024 * 1024, files: 10 } }); // do 50MB na datoteko

// omogoči streženje naloženih datotek
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

// ====== USERS ======
app.get("/users", authRequired, (req, res) => res.json(users));

app.post("/users", authRequired, requireRole(["Owner", "CEO"]), (req, res) => {
  const { email, name } = req.body || {};
  const key = String(email || "").trim().toLowerCase();
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

// ====== PROJECTS ======
app.get("/projects", authRequired, (req, res) => res.json(projects));

app.post("/projects", authRequired, requireRole(["Owner", "CEO"]), (req, res) => {
  const name = String(req.body?.name || "").trim();
  const address = String(req.body?.address || "").trim();
  if (!name) return res.status(400).json({ error: "Manjka name" });
  const proj = { id: crypto.randomUUID(), name, address: address || "" };
  projects.push(proj);
  saveProjects();
  res.status(201).json(proj);
});

app.delete("/projects/:id", authRequired, requireRole(["Owner", "CEO"]), (req, res) => {
  const id = req.params.id;
  const before = projects.length;
  projects = projects.filter(p => p.id !== id);
  if (projects.length === before) return res.status(404).json({ error: "Ni projekta" });
  saveProjects();
  res.status(204).end();
});

// ====== MATERIALS ======
app.get("/materials", authRequired, (req, res) => res.json(materials));

app.post("/materials", authRequired, (req, res) => {
  const name = String(req.body?.name || "").trim();
  const uom = String(req.body?.uom || "kos").trim();
  if (!name) return res.status(400).json({ error: "Manjka 'name'." });
  const existing = materials.find(m => m.name.toLowerCase() === name.toLowerCase());
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

// ====== PRESENCE (prisotnost) ======
/*
  type: "in" | "out" | "break-start" | "break-end"
  item = { id, email, employee, projectId, type, ts }
*/
app.post("/presence", authRequired, (req, res) => {
  const { type, projectId, ts } = req.body || {};
  const ok = ["in", "out", "break-start", "break-end"];
  if (!ok.includes(type)) return res.status(400).json({ error: "Neveljaven type" });
  const email = req.user.email;
  const employee = (users[email]?.name) || email;
  const item = {
    id: crypto.randomUUID(),
    email,
    employee,
    projectId: projectId || null,
    type,
    ts: ts || Date.now()
  };
  presence.push(item);
  savePresence();
  res.status(201).json(item);
});

app.get("/presence", authRequired, (req, res) => {
  const from = Number(req.query.from || 0);
  const to   = Number(req.query.to   || 32503680000000); // 2999-12-31
  const email = String(req.query.email || "");
  const projectId = String(req.query.projectId || "");
  const list = presence
    .filter(p => p.ts >= from && p.ts <= to)
    .filter(p => !email || p.email === email)
    .filter(p => !projectId || p.projectId === projectId)
    .sort((a,b) => a.ts - b.ts);
  res.json(list);
});

app.delete("/presence/:id", authRequired, (req, res) => {
  const id = req.params.id;
  const i = presence.findIndex(p => p.id === id);
  if (i === -1) return res.status(404).json({ error: "Ni vnosa" });
  const owner = presence[i].email === req.user.email;
  const admin = hasManagerRole(req.user) || (req.user.roles || []).includes("CEO") || (req.user.roles || []).includes("Owner");
  if (!owner && !admin) return res.status(403).json({ error: "Ni dovoljenja" });
  presence.splice(i, 1);
  savePresence();
  res.status(204).end();
});

// ====== JOB LOGS (dnevnik del) ======
/*
  item = { id, projectId, activity, hours, materials[], photos[], email, employee, ts }
  photos[] = { url, name, size, mime }
*/
app.post("/jobs", authRequired, (req, res) => {
  const { projectId, activity, hours, materials: mats, photos } = req.body || {};
  if (!projectId || !String(activity || "").trim()) {
    return res.status(400).json({ error: "Manjka projectId ali activity" });
  }
  const email = req.user.email;
  const employee = users[email]?.name || email;
  const item = {
    id: crypto.randomUUID(),
    projectId,
    activity: String(activity).trim(),
    hours: Number(hours || 0),
    materials: Array.isArray(mats) ? mats : [],
    photos: Array.isArray(photos) ? photos : [],
    email,
    employee,
    ts: Date.now()
  };
  jobs.push(item);
  saveJobs();
  res.status(201).json(item);
});

app.get("/jobs", authRequired, (req, res) => {
  const from = Number(req.query.from || 0);
  const to   = Number(req.query.to   || 32503680000000);
  const email = String(req.query.email || "");
  const projectId = String(req.query.projectId || "");
  const list = jobs
    .filter(j => j.ts >= from && j.ts <= to)
    .filter(j => !email || j.email === email)
    .filter(j => !projectId || j.projectId === projectId)
    .sort((a,b) => b.ts - a.ts);
  res.json(list);
});

// ----- Upload fotografij/videa -----
app.post("/upload", authRequired, upload.array("photos", 10), (req, res) => {
  const files = (req.files || []).map(f => ({
    url: `/uploads/${f.filename}`,
    name: f.originalname || f.filename,
    size: f.size,
    mime: f.mimetype
  }));
  res.json({ files });
});

// ====== Workplan (mesečni plan) ======
// Struktura, ki jo pričakuje frontend: { days: { 'YYYY-MM-DD': [ { projectId, people:[email], note, statuses?: { [email]:'V teku'|'Opravljeno' } } ] } }

app.get("/workplan/month", authRequired, (req, res) => {
  try {
    const { start } = req.query;
    if (!start) return res.status(400).json({ error: "Manjka parameter start" });

    const yearMonth = String(start).slice(0, 7); // YYYY-MM
    const planFile = path.join(P.workplans, `plan-${yearMonth}.json`);

    if (fs.existsSync(planFile)) {
      const data = JSON.parse(fs.readFileSync(planFile, "utf8"));
      return res.json(data && typeof data === "object" ? data : { days: {} });
    }
    return res.json({ days: {} });
  } catch (e) {
    console.error("GET /workplan/month error:", e);
    res.status(500).json({ error: "Napaka pri branju plana" });
  }
});

/**
 * PUT /workplan/month
 * Managerji (Owner/CEO/vodja): lahko zamenjajo celoten mesec (days)
 * Zaposleni/študent: lahko posodobijo SAMO svoj status (statuses[email]) pri postavkah, kjer so v people.
 *  - Strežnik v tem primeru izvede MERGE nad obstoječim planom in ignorira vse druge spremembe.
 */
app.put("/workplan/month", authRequired, (req, res) => {
  try {
    const { start, days } = req.body || {};
    if (!start || typeof days !== "object") return res.status(400).json({ error: "Manjka parameter start ali days" });

    const yearMonth = String(start).slice(0, 7); // YYYY-MM
    const planFile = path.join(P.workplans, `plan-${yearMonth}.json`);

    const exists = fs.existsSync(planFile);
    const current = exists ? JSON.parse(fs.readFileSync(planFile, "utf8")) : { days: {} };
    if (!current || typeof current !== "object" || typeof current.days !== "object") {
      current.days = {};
    }

    const isManager = hasManagerRole(req.user);

    if (isManager) {
      // Managerji zamenjajo celoten mesec
      fs.writeFileSync(planFile, JSON.stringify({ days }, null, 2));
      return res.json({ success: true, mode: "replace" });
    }

    // Zaposleni/študent -> samo merge osebnih statusov
    const email = req.user.email;
    const merged = { days: { ...current.days } };

    // Sprehodimo se po dneh, ki jih je poslal klient
    for (const dayKey of Object.keys(days || {})) {
      const incomingArr = Array.isArray(days[dayKey]) ? days[dayKey] : [];
      const existingArr = Array.isArray(merged.days[dayKey]) ? merged.days[dayKey] : [];

      // Po indeksih: klient uporablja isti vrstni red (frontend ne dodaja/briše v employee pogledu)
      const max = Math.min(incomingArr.length, existingArr.length);
      for (let i = 0; i < max; i++) {
        const inc = incomingArr[i] || {};
        const ex  = existingArr[i] || {};

        // Update dovolimo samo, če je uporabnik v people
        const people = Array.isArray(ex.people) ? ex.people : [];
        if (!people.includes(email)) continue;

        // Če je v inc.statuses podan status za trenutnega userja, ga zapišemo v existing
        const incStatuses = (inc.statuses && typeof inc.statuses === "object") ? inc.statuses : {};
        if (Object.prototype.hasOwnProperty.call(incStatuses, email)) {
          ex.statuses = ex.statuses && typeof ex.statuses === "object" ? ex.statuses : {};
          ex.statuses[email] = incStatuses[email];
          existingArr[i] = ex; // zapiši nazaj
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

// ====== statika (frontend) ======
app.use("/", express.static(WEB_DIR, { index: "index.html", fallthrough: true }));
app.get("/", (req, res) => res.sendFile(path.join(WEB_DIR, "index.html")));

// (neobvezno) Healthcheck
app.get("/healthz", (req, res) => res.json({ ok: true }));

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
  console.log(`Serving WEB from: ${WEB_DIR}`);
  console.log(`DATA dir: ${DATA_DIR}`);
});
