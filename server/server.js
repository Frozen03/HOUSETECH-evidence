// server.js — POPRAVLJENO: express.json + cors + persistenca + vsi API-ji
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

// ===== middleware (manjkalo!) =====
app.use(cors({ origin: CORS_ORIGIN }));
app.use(express.json({ limit: "10mb" }));

// ===== persistenca =====
const DATA_DIR = process.env.DATA_DIR || path.resolve(__dirname, "../data"); // na Renderju npr. /data
const WEB_DIR  = process.env.WEB_DIR  || path.resolve(__dirname, "../web");

fs.mkdirSync(DATA_DIR, { recursive: true });
fs.mkdirSync(path.join(DATA_DIR, "uploads"), { recursive: true });

const P = {
  users:      path.join(DATA_DIR, "users.json"),
  projects:   path.join(DATA_DIR, "projects.json"),
  materials:  path.join(DATA_DIR, "materials.json"),
  presence:   path.join(DATA_DIR, "presence.json"),
  jobs:       path.join(DATA_DIR, "jobs.json"),
  workplans:  path.join(DATA_DIR, "workplans"),
  todos:      path.join(DATA_DIR, "todos.json"),
  projUploads:path.join(DATA_DIR, "uploads", "projects"),
};
fs.mkdirSync(P.workplans,   { recursive: true });
fs.mkdirSync(P.projUploads, { recursive: true });

function readJSON(file, fallback) { try { return JSON.parse(fs.readFileSync(file, "utf8")); } catch { return fallback; } }
function writeJSON(file, data) { fs.writeFileSync(file, JSON.stringify(data, null, 2)); }

let users     = readJSON(P.users, {});
let projects  = readJSON(P.projects, []);
let materials = readJSON(P.materials, []);
let presence  = readJSON(P.presence, []);
let jobs      = readJSON(P.jobs, []);
let todos = readJSON(P.todos, []);     
const saveTodos = () => writeJSON(P.todos, todos);

const saveUsers     = () => writeJSON(P.users, users);
const saveProjects  = () => writeJSON(P.projects, projects);
const saveMaterials = () => writeJSON(P.materials, materials);
const savePresence  = () => writeJSON(P.presence, presence);
const saveJobs      = () => writeJSON(P.jobs, jobs);

// ===== Google OAuth =====
if (!GOOGLE_CLIENT_ID) console.warn("⚠️ GOOGLE_CLIENT_ID manjka – prijava ne bo delovala.");
const googleClient = new OAuth2Client(GOOGLE_CLIENT_ID);

// ===== JWT helperji =====
function signJWT(email, roles) { return jwt.sign({ sub: email, roles: roles || [] }, JWT_SECRET, { expiresIn: "7d" }); }
function authRequired(req, res, next) {
  try {
    const hdr = req.headers.authorization || "";
    const token = hdr.startsWith("Bearer ") ? hdr.slice(7) : null;
    if (!token) return res.status(401).json({ error: "Manjka žeton" });
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = { email: payload.sub, roles: payload.roles || [] };
    next();
  } catch {
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

// ===== upload =====
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, path.join(DATA_DIR, "uploads")),
  filename: (req, file, cb) => cb(null, crypto.randomUUID() + (path.extname(file.originalname || "").toLowerCase() || "")),
});
const upload = multer({ storage, limits: { fileSize: 50 * 1024 * 1024, files: 10 } });
app.use("/uploads", express.static(path.join(DATA_DIR, "uploads")));

const projStorage = multer.diskStorage({
  destination: (req, file, cb) => {
    const pid = req.params.id;
    const dir = path.join(P.projUploads, pid);
    fs.mkdirSync(dir, { recursive: true });
    cb(null, dir);
  },
  filename: (req, file, cb) => cb(null, crypto.randomUUID() + (path.extname(file.originalname||"").toLowerCase() || "")),
});
const projUpload = multer({ storage: projStorage, limits: { fileSize: 100 * 1024 * 1024, files: 20 } });

// ===== auth =====
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
    res.json({ access_token: token, user: { email, name: u.name || email, roles: u.roles || [] } });
  } catch (e) {
    console.error("Google verify error:", e.message);
    res.status(401).json({ error: "Neuspešna verifikacija" });
  }
});

// ===== USERS =====
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
  if ((users[email].roles || []).includes("Owner")) return res.status(403).json({ error: "Ownerja ni dovoljeno izbrisati." });
  delete users[email];
  saveUsers();
  res.status(204).end();
});

// ===== PROJECTS =====
app.get("/projects", authRequired, (req, res) => {
  const isMgr = hasManagerRole(req.user);
  if (isMgr) return res.json(projects);
  // zaposleni vidijo le odklenjene
  return res.json(projects.filter(p => !p.locked));
});

app.post("/projects", authRequired, requireRole(["Owner", "CEO"]), (req, res) => {
  const name = String(req.body?.name || "").trim();
  const address = String(req.body?.address || "").trim();
  if (!name) return res.status(400).json({ error: "Manjka name" });
  const proj = { id: crypto.randomUUID(), name, address: address || "", locked: false };
  projects.push(proj);
  saveProjects();
  res.status(201).json(proj);
});

// PATCH za preimenovanje / naslov / zaklep
app.patch("/projects/:id", authRequired, requireRole(["Owner", "CEO"]), (req, res) => {
  const id = req.params.id;
  const i = projects.findIndex(p => p.id === id);
  if (i === -1) return res.status(404).json({ error: "Ni projekta" });

  const { name, address, locked } = req.body || {};
  if (typeof name === "string") projects[i].name = name.trim();
  if (typeof address === "string") projects[i].address = address.trim();
  if (typeof locked !== "undefined") projects[i].locked = !!locked;
  saveProjects();
  res.json(projects[i]);
});

app.delete("/projects/:id", authRequired, requireRole(["Owner", "CEO"]), (req, res) => {
  const id = req.params.id;
  const before = projects.length;
  projects = projects.filter(p => p.id !== id);
  if (projects.length === before) return res.status(404).json({ error: "Ni projekta" });
  saveProjects();
  res.status(204).end();
});


// MEDIA (slike/video) iz dnevnikov po projektu
app.get("/projects/:id/media", authRequired, (req, res) => {
  const id = req.params.id;

  const list = jobs
    .filter(j => j.projectId === id)
    .flatMap(j =>
      Array.isArray(j.photos)
        ? j.photos.map(ph => ({ ...ph, __jts: j.ts, __jmail: j.email }))
        : []
    )
    .filter(ph =>
      typeof ph?.url === "string" &&
      (((ph.type || ph.mime || "").startsWith("image/")) ||
       ((ph.type || ph.mime || "").startsWith("video/")))
    )
    .map(ph => ({
      id:   ph.id  || crypto.randomUUID(),
      url:  ph.url,
      type: ph.type || ph.mime || "image/*",
      ts:   ph.ts   || ph.__jts   || Date.now(),
      by:   ph.by   || ph.__jmail || ""
    }))
    .sort((a,b) => b.ts - a.ts);

  res.json(list);
});

function getProjectById(id){ return projects.find(p=>p.id===id); }
function ensureProjFilesArray(p){ if(!Array.isArray(p.files)) p.files = []; }

// SEZNAM datotek projekta
app.get("/projects/:id/files", authRequired, (req, res) => {
  const p = getProjectById(req.params.id);
  if(!p) return res.status(404).json({ error: "Ni projekta" });
  ensureProjFilesArray(p);
  res.json(p.files);
});

// UPLOAD (managerji)
app.post("/projects/:id/files", authRequired, requireRole(["Owner","CEO","vodja"]), projUpload.array("file", 20), (req, res) => {
  const p = getProjectById(req.params.id);
  if(!p) return res.status(404).json({ error: "Ni projekta" });
  ensureProjFilesArray(p);

  const items = (req.files || []).map(f => {
    const url = `/uploads/projects/${req.params.id}/${f.filename}`;
    const meta = {
      id: crypto.randomUUID(),
      filename: f.filename,
      originalName: f.originalname,
      type: f.mimetype,
      size: f.size,
      url,
      by: req.user.email,
      ts: Date.now()
    };
    p.files.push(meta);
    return meta;
  });
  saveProjects();
  res.status(201).json(items);
});

// DELETE file (managerji)
app.delete("/projects/:id/files/:fid", authRequired, requireRole(["Owner","CEO","vodja"]), (req, res) => {
  const p = getProjectById(req.params.id);
  if(!p) return res.status(404).json({ error: "Ni projekta" });
  ensureProjFilesArray(p);

  const i = p.files.findIndex(f => f.id === req.params.fid);
  if(i === -1) return res.status(404).json({ error: "Ni datoteke" });

  const filePath = path.join(P.projUploads, req.params.id, p.files[i].filename);
  try { if (fs.existsSync(filePath)) fs.unlinkSync(filePath); } catch {}
  p.files.splice(i,1);
  saveProjects();
  res.status(204).end();
});


// ToDo – seznam
app.get("/projects/:id/todos", authRequired, requireRole(["Owner","CEO","vodja"]), (req, res) => {
  res.json(todos.filter(t=>t.projectId===req.params.id).sort((a,b)=>a.ts-b.ts));
});

// ToDo – dodaj
app.post("/projects/:id/todos", authRequired, requireRole(["Owner","CEO","vodja"]), (req,res)=>{
  const text = String(req.body?.text||"").trim();
  if(!text) return res.status(400).json({ error: "Manjka text" });
  const item = { id: crypto.randomUUID(), projectId: req.params.id, text, done:false, ts: Date.now(), by: req.user.email };
  todos.push(item); saveTodos();
  res.status(201).json(item);
});

// ToDo – spremeni
app.patch("/projects/:id/todos/:tid", authRequired, requireRole(["Owner","CEO","vodja"]), (req,res)=>{
  const i = todos.findIndex(t=>t.id===req.params.tid && t.projectId===req.params.id);
  if(i===-1) return res.status(404).json({ error:"Ni naloge" });
  const { text, done } = req.body||{};
  if(typeof text==="string") todos[i].text = text.trim();
  if(typeof done==="boolean") todos[i].done = done;
  saveTodos();
  res.json(todos[i]);
});

// ToDo – izbriši
app.delete("/projects/:id/todos/:tid", authRequired, requireRole(["Owner","CEO","vodja"]), (req,res)=>{
  const before = todos.length;
  todos = todos.filter(t=>!(t.id===req.params.tid && t.projectId===req.params.id));
  if(before===todos.length) return res.status(404).json({ error:"Ni naloge" });
  saveTodos();
  res.status(204).end();
});


// ===== MATERIALS =====
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

// ===== PRESENCE =====
app.post("/presence", authRequired, (req, res) => {
  const { type, projectId, ts } = req.body || {};
  const ok = ["in", "out", "break-start", "break-end"];
  if (!ok.includes(type)) return res.status(400).json({ error: "Neveljaven type" });
  const email = req.user.email;
  const employee = users[email]?.name || email;
  const item = { id: crypto.randomUUID(), email, employee, projectId: projectId || null, type, ts: ts || Date.now() };
  presence.push(item);
  savePresence();
  res.status(201).json(item);
});

app.get("/presence", authRequired, (req, res) => {
  const from = Number(req.query.from || 0);
  const to   = Number(req.query.to   || 32503680000000);
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
  const admin = (req.user.roles || []).some(r => r === "Owner" || r === "CEO");
  if (!owner && !admin) return res.status(403).json({ error: "Ni dovoljenja" });
  presence.splice(i, 1);
  savePresence();
  res.status(204).end();
});

// ===== REPORTS =====

// helper: parsa IN/OUT/break v efektivne ure
function computePresenceHours(records){
  // records: vse prisotnosti znotraj časovnega okna (že filtrirane)
  // vrača { byProject:{[projectId]: hours}, byEmployee:{[email]: hours}, rows:[{date,projectId,email,hours}] }
  const byKey = {}; // ključ: date|email|projectId -> array of events
  for(const r of records){
    const d = new Date(r.ts);
    const date = new Date(d.getFullYear(), d.getMonth(), d.getDate()).toISOString().slice(0,10);
    const key = `${date}|${r.email}|${r.projectId||''}`;
    (byKey[key] ||= []).push(r);
  }

  const byProject = {};
  const byEmployee = {};
  const rows = [];

  for(const [key, arr] of Object.entries(byKey)){
    const [date, email, projectId] = key.split('|');
    const list = arr.slice().sort((a,b)=>a.ts-b.ts);

    let totalMs = 0;
    let inAt = null;
    let breakStart = null;
    let breakMs = 0;

    for(const ev of list){
      if (ev.type === 'in'){
        inAt = ev.ts;
        breakStart = null; breakMs = 0;
      } else if (ev.type === 'break-start' && inAt != null){
        if (breakStart == null) breakStart = ev.ts;
      } else if (ev.type === 'break-end' && inAt != null && breakStart != null){
        breakMs += Math.max(0, ev.ts - breakStart);
        breakStart = null;
      } else if (ev.type === 'out' && inAt != null){
        const span = Math.max(0, ev.ts - inAt);
        const eff = Math.max(0, span - breakMs);
        totalMs += eff;
        inAt = null; breakStart = null; breakMs = 0;
      }
    }

    const hours = Math.round((totalMs/3600000)*100)/100;
    if (hours > 0){
      const pid = projectId || '';
      byProject[pid] = (byProject[pid] || 0) + hours;
      byEmployee[email] = (byEmployee[email] || 0) + hours;
      rows.push({ date, projectId: pid, email, hours });
    }
  }

  return { byProject, byEmployee, rows };
}

app.get("/reports/summary", authRequired, async (req, res) => {
  try{
    const from = Number(req.query.from || 0);
    const to   = Number(req.query.to   || 32503680000000);
    const projectId = String(req.query.projectId || "");
    const email     = String(req.query.email || "");

    const isMgr = hasManagerRole(req.user);
    const myEmail = req.user.email;

    // Presence
    let pres = presence
      .filter(p => p.ts >= from && p.ts <= to)
      .filter(p => !projectId || p.projectId === projectId)
      .filter(p => !email || p.email === email);

    // Jobs
    let jlist = jobs
      .filter(j => j.ts >= from && j.ts <= to)
      .filter(j => !projectId || j.projectId === projectId)
      .filter(j => !email || j.email === email);

    // Filtri za zaposlene (zaklenjeni projekti + samo njihove zadeve)
    if (!isMgr){
      pres = pres
        .filter(p => p.email === myEmail)
        .filter(p => {
          if (!p.projectId) return true;
          const pr = projects.find(x => x.id === p.projectId);
          return !(pr && pr.locked);
        });

      jlist = jlist
        .filter(j => j.email === myEmail)
        .filter(j => {
          const pr = projects.find(x => x.id === j.projectId);
          return !(pr && pr.locked);
        });
    }

    const presAgg = computePresenceHours(pres);

    // Jobs aggregations
    const jobsByProject = {};
    const jobsByEmployee = {};
    jlist.forEach(j => {
      jobsByProject[j.projectId] = (jobsByProject[j.projectId] || 0) + Number(j.hours || 0);
      jobsByEmployee[j.email] = (jobsByEmployee[j.email] || 0) + Number(j.hours || 0);
    });

    res.json({
      presence: {
        byProject: presAgg.byProject,
        byEmployee: presAgg.byEmployee,
        rows: presAgg.rows
      },
      jobs: {
        byProject: jobsByProject,
        byEmployee: jobsByEmployee,
        rows: jlist.map(j => ({ date: new Date(j.ts).toISOString().slice(0,10), projectId: j.projectId, email: j.email, activity: j.activity, hours: Number(j.hours||0) }))
      }
    });
  }catch(e){
    console.error("GET /reports/summary error:", e);
    res.status(500).json({ error: "Napaka pri poročilih" });
  }
});


// ===== JOBS =====
function isProjectLocked(projectId){
  if (!projectId) return false;
  const p = projects.find(x => x.id === projectId);
  return !!(p && p.locked);
}

function upsertMaterialsFromLogs(mats){
  if (!Array.isArray(mats)) return;
  let changed = false;
  mats.forEach(m=>{
    const name = String(m?.name||"").trim();
    if (!name) return;
    const uom  = String(m?.uom||"kos").trim() || "kos";
    const hit = materials.find(x => (x.name||"").toLowerCase() === name.toLowerCase());
    if (hit){
      // če je uom nov, ga posodobi (ne rušimo ID)
      if (uom && uom !== hit.uom){ hit.uom = uom; changed = true; }
    }else{
      materials.push({ id: crypto.randomUUID(), name, uom });
      changed = true;
    }
  });
  if (changed) saveMaterials();
}


app.post("/jobs", authRequired, (req, res) => {
  const { projectId, activity, hours, materials: mats, photos } = req.body || {};
  if (!projectId || !activity) return res.status(400).json({ error: "Manjka projectId ali activity" });

  // zaposleni/študent ne sme v zaklenjen projekt
  const isMgr = hasManagerRole(req.user);
  if (!isMgr && isProjectLocked(projectId)) {
    return res.status(403).json({ error: "Projekt je zaklenjen." });
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
  upsertMaterialsFromLogs(item.materials);
  res.status(201).json(item);
});

app.get("/jobs", authRequired, (req, res) => {
  const from = Number(req.query.from || 0);
  const to   = Number(req.query.to   || 32503680000000);
  const emailQ = String(req.query.email || "");
  const projectId = String(req.query.projectId || "");

  const isMgr = hasManagerRole(req.user);
  const myEmail = req.user.email;

  let list = jobs
    .filter(j => j.ts >= from && j.ts <= to)
    .filter(j => !projectId || j.projectId === projectId);

  // zaposleni: vidijo le svoje in ne-locked projekte
  if (!isMgr) {
    list = list
      .filter(j => j.email === myEmail)
      .filter(j => !isProjectLocked(j.projectId));
  } else {
    // managerji lahko še dodatno filtrirajo po emailu
    if (emailQ) list = list.filter(j => j.email === emailQ);
  }

  list = list.sort((a,b) => b.ts - a.ts);
  res.json(list);
});

app.put("/jobs/:id", authRequired, (req, res) => {
  try {
    const id = req.params.id;
    const idx = jobs.findIndex(j => j.id === id);
    if (idx === -1) return res.status(404).json({ error: "Dnevnik ne obstaja" });

    const j = jobs[idx];
    const admin = hasManagerRole(req.user);
    const owner = j.email === req.user.email;
    if (!admin && !owner) return res.status(403).json({ error: "Ni dovoljenja" });

    const { projectId, activity, hours, materials: mats, photos } = req.body || {};

    // če ni manager, ne dovoli prestavit v zaklenjen projekt
    if (!admin && projectId && isProjectLocked(projectId)) {
      return res.status(403).json({ error: "Projekt je zaklenjen." });
    }

    if (typeof projectId === "string" && projectId.trim()) j.projectId = projectId.trim();
    if (typeof activity === "string") j.activity = activity.trim();
    if (typeof hours !== "undefined" && !Number.isNaN(Number(hours))) j.hours = Number(hours);
    if (Array.isArray(mats)) j.materials = mats;
    if (Array.isArray(photos)) j.photos = photos;

    saveJobs();
    upsertMaterialsFromLogs(j.materials);
    res.json(j);
  } catch (e) {
    console.error("PUT /jobs/:id error:", e);
    res.status(500).json({ error: "Napaka pri posodobitvi dnevnika" });
  }
});

app.delete("/jobs/:id", authRequired, (req, res) => {
  try {
    const id = req.params.id;
    const idx = jobs.findIndex(j => j.id === id);
    if (idx === -1) return res.status(404).json({ error: "Dnevnik ne obstaja" });

    const j = jobs[idx];
    const admin = hasManagerRole(req.user);
    const owner = j.email === req.user.email;
    if (!admin && !owner) return res.status(403).json({ error: "Ni dovoljenja" });

    jobs.splice(idx, 1);
    saveJobs();
    res.status(204).end();
  } catch (e) {
    console.error("DELETE /jobs/:id error:", e);
    res.status(500).json({ error: "Napaka pri brisanju dnevnika" });
  }
});




// ===== upload fotografij =====
app.post("/upload", authRequired, upload.array("photos", 10), (req, res) => {
  const files = (req.files || []).map(f => ({
    url: `/uploads/${f.filename}`,
    name: f.originalname || f.filename,
    size: f.size,
    mime: f.mimetype
  }));
  res.json({ files });
});

// ===== helper: normalizacija people -> email =====
function toEmailLike(val) {
  if (!val) return val;
  const s = String(val).trim();
  if (!s) return s;
  if (s.includes("@")) return s.toLowerCase();
  const hit = Object.entries(users).find(([,u]) => (u?.name || "").toLowerCase() === s.toLowerCase());
  return hit ? hit[0].toLowerCase() : s;
}

// ===== Workplan (mesečni plan) =====
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
      return res.json(raw || { days: {} });
    }
    res.json({ days: {} });
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

    // zaposleni: posodobijo samo svoj status
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
  const current = ex.statuses[email] || 'V teku';
  const incoming = incStatuses[email];
  // če je že Opravljeno, ne dovolimo spremembe nazaj
  if (current === 'Opravljeno' && incoming !== 'Opravljeno') {
    // ignoriraj poskus spremembe
  } else {
    ex.statuses[email] = incoming;
  }
  existingArr[i] = ex;
}
        }
      }
      merged.days[dayKey] = existingArr;
    }
    fs.writeFileSync(planFile, JSON.stringify(merged, null, 2));
    res.json({ success: true, mode: "merge-status" });
  } catch (e) {
    console.error("PUT /workplan/month error:", e);
    res.status(500).json({ error: "Napaka pri shranjevanju plana" });
  }
});

// ===== statika =====
app.use("/", express.static(WEB_DIR, { index: "index.html" }));
app.get("/", (req, res) => res.sendFile(path.join(WEB_DIR, "index.html")));

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
  console.log(`Serving WEB from: ${WEB_DIR}`);
  console.log(`DATA dir: ${DATA_DIR}`);
});
