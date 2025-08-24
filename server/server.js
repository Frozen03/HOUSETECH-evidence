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

// ----- CORS & body -----
app.use(cors({ origin: CORS_ORIGIN }));
app.use(express.json({ limit: "10mb" }));

// ----- Poti do podatkov -----
const DATA_DIR = process.env.DATA_DIR || "/data";               // Render disk
const WEB_DIR  = path.join(__dirname, "../web");

fs.mkdirSync(DATA_DIR, { recursive: true });
fs.mkdirSync(path.join(DATA_DIR, "uploads"), { recursive: true });

const P = {
  users:      path.join(DATA_DIR, "users.json"),
  projects:   path.join(DATA_DIR, "projects.json"),
  materials:  path.join(DATA_DIR, "materials.json"),
  presence:   path.join(DATA_DIR, "presence.json"),
  jobs:       path.join(DATA_DIR, "jobs.json")
};

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

// ----- Upload (fotografije) -----
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, path.join(DATA_DIR, "uploads")),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    cb(null, crypto.randomUUID() + ext.toLowerCase());
  }
});
const upload = multer({ storage });

// omogoči streženje naloženih slik
app.use("/uploads", express.static(path.join(DATA_DIR, "uploads")));

// ----- Auth -----
app.post("/auth/google/verify", async (req, res) => {
  try {
    const { credential } = req.body || {};
    if (!credential) return res.status(400).json({ error: "Manjka credential" });

    const ticket = await googleClient.verifyIdToken({
      idToken: credential,
      audience: GOOGLE_CLIENT_ID
    });
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

// ----- USERS -----
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

<script>
// === POMOČNE ===
const monthKey = ts => {
  const d = new Date(ts);
  return `${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,'0')}`; // npr. 2025-02
};
const dayKeyStr = ts => new Date(ts).toLocaleDateString('sl-SI');

// === DNEVNIK: seznam projektov + podrobnosti ===
let __drSelectedProject = null;

function renderDiaryProjectsList(){
  const ul = document.getElementById('drProjects');
  if(!ul) return;
  ul.innerHTML = (projects||[]).map(p => `
    <li>
      <button class="w-full text-left p-2 border rounded-lg hover:bg-gray-50"
              onclick="openDiaryProject('${p.id}')">
        <div class="font-medium truncate">${p.name}</div>
        ${p.address ? `<div class="text-xs text-gray-500 truncate">${p.address}</div>` : ``}
      </button>
    </li>
  `).join('') || `<li class="text-gray-500 text-sm">Ni projektov.</li>`;
}

async function openDiaryProject(projectId){
  __drSelectedProject = projectId;
  const p = projects.find(x => x.id === projectId);
  document.getElementById('drEmpty').classList.add('hidden');
  document.getElementById('drDetails').classList.remove('hidden');
  document.getElementById('drProjectTitle').textContent = p?.name || 'Projekt';
  document.getElementById('drProjectAddress').textContent = p?.address || '';

  await refreshDiaryDetails();
}

document.getElementById('drPeriod')?.addEventListener('change', () => {
  const val = document.getElementById('drPeriod').value;
  document.getElementById('drAggLabel').textContent = val === 'month' ? 'po mesecih' : 'po dnevih';
  if(__drSelectedProject) refreshDiaryDetails();
});

async function refreshDiaryDetails(){
  const pid = __drSelectedProject;
  if(!pid) return;

  // uporabimo globalna filtra Od/Do (zgornji filter v poročilih)
  const from = new Date(document.getElementById('repFrom').value || '1970-01-01'); from.setHours(0,0,0,0);
  const to   = new Date(document.getElementById('repTo').value   || '2999-12-31');  to.setHours(23,59,59,999);

  // naloži vse job vnose za ta projekt in razpon
  const qs = new URLSearchParams({ projectId: pid, from: String(from.getTime()), to: String(to.getTime()) });
  const r = await fetch(API_BASE + '/jobs?' + qs.toString(), { headers: { Authorization: 'Bearer ' + accessToken }});
  const list = r.ok ? await r.json() : [];

  renderDiaryMaterials(list);
  renderDiaryActivities(list);
  renderDiaryPhotos(list);
}

function renderDiaryMaterials(list){
  const period = document.getElementById('drPeriod').value || 'day';
  const tbody = document.getElementById('drMaterials');
  const agg = {}; // key = group|name|uom

  (list||[]).forEach(j => {
    (j.materials || []).forEach(m => {
      const group = period === 'month' ? monthKey(j.ts) : dayKeyStr(j.ts);
      const key = `${group}|${(m.name||'').trim()}|${m.uom||'kos'}`;
      agg[key] = (agg[key] || 0) + Number(m.qty || 0);
    });
  });

  const rows = Object.entries(agg)
    .map(([k, qty]) => {
      const [group, name, uom] = k.split('|');
      return { group, name, qty: +(+qty).toFixed(2), uom };
    })
    .sort((a,b) => a.group.localeCompare(b.group) || a.name.localeCompare(b.name));

  tbody.innerHTML = rows.map(r =>
    `<tr>
      <td class="border p-2">${r.group}</td>
      <td class="border p-2">${r.name}</td>
      <td class="border p-2">${r.qty}</td>
      <td class="border p-2">${r.uom}</td>
    </tr>`).join('') || `<tr><td class="border p-2 text-center text-gray-500" colspan="4">Ni materialov v izbranem obdobju.</td></tr>`;
}

function renderDiaryActivities(list){
  const mount = document.getElementById('drActivities');
  const groups = {};
  (list||[]).forEach(j => {
    const key = dayKeyStr(j.ts);
    (groups[key] ||= []).push(j);
  });

  const days = Object.keys(groups).sort((a,b)=>{
    const pa=a.split('.').reverse().join('-'), pb=b.split('.').reverse().join('-');
    return pa.localeCompare(pb);
  });

  mount.innerHTML = days.map(d => {
    const items = groups[d].map(j =>
      `<li class="flex items-start justify-between gap-3">
        <div class="flex-1">
          <div class="font-medium">${j.activity}</div>
          <div class="text-xs text-gray-500">${j.employee}</div>
        </div>
        <div class="text-sm">${(+j.hours||0)} h</div>
      </li>`).join('');
    return `<div class="border rounded-lg p-2">
              <div class="font-semibold mb-1">${d}</div>
              <ul class="space-y-1">${items}</ul>
            </div>`;
  }).join('') || `<div class="text-gray-500 text-sm">Ni aktivnosti.</div>`;
}

function renderDiaryPhotos(list){
  const mount = document.getElementById('drPhotos');
  const imgs = [];
  (list||[]).forEach(j => (j.photos||[]).forEach(p => imgs.push(p.url)));
  mount.innerHTML = imgs.length
    ? imgs.map(u => `<a href="${u}" target="_blank"><img src="${u}" class="w-20 h-20 object-cover rounded border"/></a>`).join('')
    : `<div class="text-gray-500 text-sm">Ni slik.</div>`;
}
</script>


// ----- PROJECTS (z naslovom) -----
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

// ----- MATERIALS -----
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

// ----- PRESENCE (prisotnost) -----
/*
  type: "in" | "out" | "break-start" | "break-end"
  item = { id, email, employee, projectId, type, ts }
*/
app.post("/presence", authRequired, (req, res) => {
  const { type, projectId, ts } = req.body || {};
  const ok = ["in", "out", "break-start", "break-end"];
  if (!ok.includes(type)) return res.status(400).json({ error: "Neveljaven type" });
  const email = req.user.email;
  const employee = users[email]?.name || email;
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
  // dovolimo brisanje lastniku ali adminom
  const owner = presence[i].email === req.user.email;
  const admin = (req.user.roles || []).some(r => r === "Owner" || r === "CEO");
  if (!owner && !admin) return res.status(403).json({ error: "Ni dovoljenja" });
  presence.splice(i, 1);
  savePresence();
  res.status(204).end();
});

// ----- JOB LOGS (dnevnik del) -----
/*
  item = { id, projectId, activity, hours, materials[], photos[], email, employee, ts }
  photos[] = { url, name, size, mime }
*/
app.post("/jobs", authRequired, (req, res) => {
  const { projectId, activity, hours, materials: mats, photos } = req.body || {};
  if (!projectId || !activity) return res.status(400).json({ error: "Manjka projectId ali activity" });
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

// ----- Upload fotografij -----
app.post("/upload", authRequired, upload.array("photos", 10), (req, res) => {
  const files = (req.files || []).map(f => ({
    url: `/uploads/${f.filename}`,
    name: f.filename,
    size: f.size,
    mime: f.mimetype
  }));
  res.json({ files });
});

// ----- statika (frontend) -----
app.use("/", express.static(WEB_DIR));
app.get("/", (req, res) => res.sendFile(path.join(WEB_DIR, "index.html")));

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
  console.log(`Serving WEB from: ${WEB_DIR}`);
  console.log(`DATA dir: ${DATA_DIR}`);
});
