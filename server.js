/** TrueClick backend (Express + SQLite). Run: npm start */
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { DatabaseSync } from "node:sqlite";
import express from "express";
import { analyze, hostOf } from "./analyzer.mjs";

const BASE = path.dirname(fileURLToPath(import.meta.url));
const DB_PATH = path.join(BASE, "trueclick.db");
const SECRET_PATH = path.join(BASE, ".secret");
const RECHECK_SECONDS = 24 * 3600;
const PORT = Number(process.env.PORT || 5000);

function loadSecret() {
  if (process.env.SECRET_KEY) return process.env.SECRET_KEY;
  if (fs.existsSync(SECRET_PATH)) return fs.readFileSync(SECRET_PATH, "utf8").trim();
  const s = crypto.randomBytes(16).toString("hex");
  fs.writeFileSync(SECRET_PATH, s);
  return s;
}
const SECRET = loadSecret();

const SCHEMA = `
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, email TEXT UNIQUE, pw TEXT, role TEXT, created REAL);
CREATE TABLE IF NOT EXISTS checks(id INTEGER PRIMARY KEY, user_id INT, url TEXT, host TEXT, score INT, label TEXT, risk TEXT, ts REAL);
CREATE TABLE IF NOT EXISTS watch(id INTEGER PRIMARY KEY, user_id INT, url TEXT, host TEXT, ad_text TEXT, page_input TEXT,
  label TEXT, score INT, history TEXT, last_checked REAL, boost INT DEFAULT 0);
CREATE TABLE IF NOT EXISTS notes(id INTEGER PRIMARY KEY, user_id INT, msg TEXT, is_read INT DEFAULT 0, ts REAL);
CREATE TABLE IF NOT EXISTS complaints(id INTEGER PRIMARY KEY, user_id INT, url TEXT, host TEXT, type TEXT, text TEXT,
  status TEXT DEFAULT 'Open', reply TEXT DEFAULT '', ts REAL, authority TEXT DEFAULT '');
CREATE TABLE IF NOT EXISTS reviews(id INTEGER PRIMARY KEY, user_id INT, host TEXT, url TEXT, verdict TEXT, text TEXT, ts REAL);
`;

const db = new DatabaseSync(DB_PATH);
db.exec(SCHEMA);
try {
  db.exec("ALTER TABLE complaints ADD COLUMN authority TEXT DEFAULT ''");
} catch {
  /* already present */
}
db.prepare("UPDATE users SET role='government' WHERE role='advertiser'").run();

const AUTHORITIES = [
  "Consumer Affairs (National Consumer Helpline 1915)",
  "Cyber Crime Cell (helpline 1930)",
  "RBI (financial fraud / Sachet)",
];

function hashPw(pw) {
  const salt = crypto.randomBytes(16).toString("hex");
  const hash = crypto.scryptSync(pw, salt, 32).toString("hex");
  return `scrypt:${salt}:${hash}`;
}
function checkPw(pw, stored) {
  try {
    const [kind, salt, hash] = String(stored).split(":");
    if (kind !== "scrypt" || !salt || !hash) return false;
    const h = crypto.scryptSync(pw, salt, 32);
    const expected = Buffer.from(hash, "hex");
    return h.length === expected.length && crypto.timingSafeEqual(h, expected);
  } catch {
    return false;
  }
}

function signSession(obj) {
  const payload = Buffer.from(JSON.stringify(obj)).toString("base64url");
  const sig = crypto.createHmac("sha256", SECRET).update(payload).digest("base64url");
  return `${payload}.${sig}`;
}
function readSession(req) {
  const raw = (req.headers.cookie || "")
    .split(";")
    .map((p) => p.trim())
    .find((p) => p.startsWith("tc="));
  if (!raw) return null;
  const token = decodeURIComponent(raw.slice(3));
  const i = token.lastIndexOf(".");
  if (i < 0) return null;
  const payload = token.slice(0, i);
  const sig = token.slice(i + 1);
  const expect = crypto.createHmac("sha256", SECRET).update(payload).digest("base64url");
  if (sig.length !== expect.length || !crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expect))) return null;
  try {
    return JSON.parse(Buffer.from(payload, "base64url").toString());
  } catch {
    return null;
  }
}
function setSession(res, obj) {
  res.setHeader("Set-Cookie", `tc=${signSession(obj)}; HttpOnly; SameSite=Lax; Path=/`);
}
function clearSession(res) {
  res.setHeader("Set-Cookie", "tc=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0");
}

const app = express();
app.disable("x-powered-by");
app.use(express.json({ limit: "3mb" }));
app.use("/static", express.static(path.join(BASE, "static")));
app.use("/samples", express.static(path.join(BASE, "samples")));
app.get("/", (_req, res) => res.sendFile(path.join(BASE, "templates", "index.html")));

function loginRequired(req, res, next) {
  const s = readSession(req);
  if (!s?.uid) return res.status(401).json({ error: "Please log in first." });
  req.user = s;
  next();
}
function govOnly(req, res, next) {
  if (req.user.role !== "government") return res.status(403).json({ error: "Only government officers can do this." });
  next();
}
const wrap = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

function community(host) {
  const revs = db.prepare("SELECT verdict FROM reviews WHERE host=?").all(host).map((r) => r.verdict);
  const oc = db.prepare("SELECT COUNT(*) AS n FROM complaints WHERE host=? AND status='Open'").get(host).n;
  return [revs, oc];
}
async function runAnalysis(url, ad, pageInput, boost = 0) {
  const h = hostOf(url);
  const [revs, oc] = community(h);
  const r = await analyze(url, ad, pageInput, boost, revs, oc);
  return [r, revs.length];
}

app.post("/api/auth", (req, res) => {
  const d = req.body || {};
  const email = String(d.email || "").trim().toLowerCase();
  const pw = String(d.password || "");
  if (!/^\S+@\S+\.\S+$/.test(email) || pw.length < 6) {
    return res.status(400).json({ error: "Enter a valid email and a password of at least 6 characters." });
  }
  let u = db.prepare("SELECT * FROM users WHERE email=?").get(email);
  if (u) {
    if (!checkPw(pw, u.pw)) return res.status(401).json({ error: "Wrong password for this email." });
  } else {
    const role = d.role === "government" ? "government" : "user";
    const info = db.prepare("INSERT INTO users(email,pw,role,created) VALUES(?,?,?,?)").run(email, hashPw(pw), role, Date.now() / 1000);
    u = db.prepare("SELECT * FROM users WHERE id=?").get(info.lastInsertRowid);
  }
  setSession(res, { uid: u.id, role: u.role, email: u.email });
  res.json({ email: u.email, role: u.role });
});

app.post("/api/logout", (_req, res) => {
  clearSession(res);
  res.json({ ok: true });
});

app.get("/api/me", (req, res) => {
  const s = readSession(req);
  if (!s?.uid) return res.json({ user: null });
  const unread = db.prepare("SELECT COUNT(*) AS n FROM notes WHERE user_id=? AND is_read=0").get(s.uid).n;
  res.json({ user: { email: s.email, role: s.role }, unread });
});

app.post("/api/check", loginRequired, wrap(async (req, res) => {
  const d = req.body || {};
  const url = String(d.url || "").trim().slice(0, 2000);
  if (!url) return res.status(400).json({ error: "Paste a link first." });
  const [r, nrev] = await runAnalysis(url, String(d.ad_text || "").slice(0, 3000), d.page_input || null);
  db.prepare("INSERT INTO checks(user_id,url,host,score,label,risk,ts) VALUES(?,?,?,?,?,?,?)").run(
    req.user.uid, url, r.host, r.score, r.label, r.risk, Date.now() / 1000,
  );
  r.reviews = nrev;
  res.json(r);
}));

app.get("/api/history", loginRequired, (req, res) => {
  res.json(db.prepare("SELECT url,host,score,label,risk,ts FROM checks WHERE user_id=? ORDER BY id DESC LIMIT 20").all(req.user.uid));
});

function notify(uid, msg) {
  db.prepare("INSERT INTO notes(user_id,msg,ts) VALUES(?,?,?)").run(uid, msg, Date.now() / 1000);
}

async function recheck(w, forceBoost = 0) {
  const boost = (w.boost || 0) + forceBoost;
  const [revs, oc] = community(w.host);
  const r = await analyze(w.url, w.ad_text || "", w.page_input || null, boost, revs, oc);
  const hist = JSON.parse(w.history).concat([r.score]);
  const prev = w.label;
  if (prev === "Not suggested" && (r.label === "Good" || r.label === "Excellent")) {
    notify(w.user_id, `${w.host} is now rated ${r.label} (${r.score}/100). It was 'Not suggested' earlier.`);
  } else if ((prev === "Good" || prev === "Excellent") && r.label === "Not suggested") {
    notify(w.user_id, `Warning: ${w.host} dropped to 'Not suggested' (${r.score}/100).`);
  }
  db.prepare("UPDATE watch SET label=?,score=?,history=?,last_checked=?,boost=? WHERE id=?").run(
    r.label, r.score, JSON.stringify(hist.slice(-15)), Date.now() / 1000, boost, w.id,
  );
}

app.post("/api/watch", loginRequired, wrap(async (req, res) => {
  const d = req.body || {};
  const url = String(d.url || "").trim();
  if (!hostOf(url)) return res.status(400).json({ error: "Invalid link." });
  if (db.prepare("SELECT 1 AS x FROM watch WHERE user_id=? AND url=?").get(req.user.uid, url)) {
    return res.status(409).json({ error: "Already on your watchlist." });
  }
  const [r] = await runAnalysis(url, d.ad_text || "", d.page_input || null);
  db.prepare(
    "INSERT INTO watch(user_id,url,host,ad_text,page_input,label,score,history,last_checked) VALUES(?,?,?,?,?,?,?,?,?)",
  ).run(req.user.uid, url, r.host, String(d.ad_text || "").slice(0, 3000), d.page_input || null, r.label, r.score, JSON.stringify([r.score]), Date.now() / 1000);
  res.json({ ok: true });
}));

app.get("/api/watch", loginRequired, (req, res) => {
  const out = db.prepare("SELECT id,url,host,label,score,history,last_checked FROM watch WHERE user_id=? ORDER BY id DESC").all(req.user.uid);
  for (const o of out) o.history = JSON.parse(o.history);
  res.json(out);
});

app.post("/api/watch/:wid/recheck", loginRequired, wrap(async (req, res) => {
  const w = db.prepare("SELECT * FROM watch WHERE id=? AND user_id=?").get(Number(req.params.wid), req.user.uid);
  if (!w) return res.status(404).json({ error: "Not found." });
  const demo = (req.body || {}).demo ? 40 : 0;
  await recheck(w, demo);
  res.json({ ok: true });
}));

app.delete("/api/watch/:wid", loginRequired, (req, res) => {
  db.prepare("DELETE FROM watch WHERE id=? AND user_id=?").run(Number(req.params.wid), req.user.uid);
  res.json({ ok: true });
});

app.get("/api/notes", loginRequired, (req, res) => {
  const out = db.prepare("SELECT id,msg,is_read,ts FROM notes WHERE user_id=? ORDER BY id DESC LIMIT 50").all(req.user.uid);
  db.prepare("UPDATE notes SET is_read=1 WHERE user_id=?").run(req.user.uid);
  res.json(out);
});

app.get("/api/complaints", loginRequired, (req, res) => {
  if (req.user.role === "government") {
    return res.json(db.prepare("SELECT c.*, u.email AS who FROM complaints c JOIN users u ON u.id=c.user_id ORDER BY c.id DESC").all());
  }
  res.json(db.prepare("SELECT * FROM complaints WHERE user_id=? ORDER BY id DESC").all(req.user.uid));
});

app.post("/api/complaints", loginRequired, (req, res) => {
  const d = req.body || {};
  const url = String(d.url || "").trim();
  const text = String(d.text || "").trim();
  if (!hostOf(url) || text.length < 5) return res.status(400).json({ error: "Add a valid link and describe the problem." });
  const authority = AUTHORITIES.includes(d.authority) ? d.authority : AUTHORITIES[0];
  const issue = String(d.type || "").trim().slice(0, 120) || "Other";
  db.prepare("INSERT INTO complaints(user_id,url,host,type,text,ts,authority) VALUES(?,?,?,?,?,?,?)").run(
    req.user.uid, url.slice(0, 2000), hostOf(url), issue, text.slice(0, 2000), Date.now() / 1000, authority,
  );
  res.json({ ok: true });
});

app.post("/api/complaints/:cid/resolve", loginRequired, govOnly, (req, res) => {
  const c = db.prepare("SELECT * FROM complaints WHERE id=?").get(Number(req.params.cid));
  if (!c) return res.status(404).json({ error: "Not found." });
  const d = req.body || {};
  const status = d.status === "Under review" ? "Under review" : "Resolved";
  const reply = String(d.reply || (status === "Under review" ? "Your complaint is being reviewed." : "Action has been taken.")).slice(0, 1000);
  db.prepare("UPDATE complaints SET status=?, reply=? WHERE id=?").run(status, reply, c.id);
  notify(c.user_id, `${c.authority || "The government desk"} marked your complaint about ${c.host} as ${status}: ${reply}`);
  res.json({ ok: true });
});

app.get("/api/reviews", loginRequired, (req, res) => {
  const q = String(req.query.host || "").trim().toLowerCase();
  if (q) return res.json(db.prepare("SELECT host,verdict,text,ts FROM reviews WHERE host LIKE ? ORDER BY id DESC LIMIT 50").all(`%${q}%`));
  res.json(db.prepare("SELECT host,verdict,text,ts FROM reviews ORDER BY id DESC LIMIT 50").all());
});

app.post("/api/reviews", loginRequired, (req, res) => {
  const d = req.body || {};
  const url = String(d.url || "").trim();
  const text = String(d.text || "").trim();
  if (!hostOf(url) || text.length < 5) return res.status(400).json({ error: "Add a valid link and a short review." });
  const verdict = d.verdict === "Genuine" ? "Genuine" : "Misleading";
  db.prepare("INSERT INTO reviews(user_id,host,url,verdict,text,ts) VALUES(?,?,?,?,?,?)").run(
    req.user.uid, hostOf(url), url.slice(0, 2000), verdict, text.slice(0, 2000), Date.now() / 1000,
  );
  res.json({ ok: true });
});

setInterval(async () => {
  try {
    const cutoff = Date.now() / 1000 - RECHECK_SECONDS;
    const rows = db.prepare("SELECT * FROM watch WHERE last_checked < ?").all(cutoff);
    for (const w of rows) await recheck(w);
  } catch (e) {
    console.log("background re-check error:", e);
  }
}, 600_000);

app.use((err, _req, res, _next) => {
  console.error(err);
  res.status(500).json({ error: err.message || "Server error" });
});

app.listen(PORT, "127.0.0.1", () => {
  console.log(`TrueClick running at http://127.0.0.1:${PORT} | LLM: ${process.env.ANTHROPIC_API_KEY ? "ON" : "OFF (rule-based mode)"}`);
});
