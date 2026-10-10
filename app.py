"""TrueClick backend (Flask + SQLite).  Run:  python app.py"""
import json
import os
import re
import secrets
import sqlite3
import threading
import time
from datetime import datetime, timezone
from functools import wraps

from flask import Flask, g, jsonify, render_template, request, send_from_directory, session
from werkzeug.security import check_password_hash, generate_password_hash

import analyzer

try:  # optional: load ANTHROPIC_API_KEY from .env
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

BASE = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE, "trueclick.db")
RECHECK_SECONDS = 24 * 3600

def _secret():
    env = os.getenv("SECRET_KEY")
    if env:
        return env
    path = os.path.join(BASE, ".secret")
    if os.path.exists(path):
        return open(path, encoding="utf-8").read().strip()
    val = secrets.token_hex(16)
    open(path, "w", encoding="utf-8").write(val)
    return val


app = Flask(__name__, template_folder=os.path.join(BASE, "templates"), static_folder=os.path.join(BASE, "static"))
app.secret_key = _secret()
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax", MAX_CONTENT_LENGTH=3_000_000)

SCHEMA = """
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, email TEXT UNIQUE, pw TEXT, role TEXT, created REAL);
CREATE TABLE IF NOT EXISTS checks(id INTEGER PRIMARY KEY, user_id INT, url TEXT, host TEXT, score INT, label TEXT, risk TEXT, ts REAL);
CREATE TABLE IF NOT EXISTS watch(id INTEGER PRIMARY KEY, user_id INT, url TEXT, host TEXT, ad_text TEXT, page_input TEXT,
  label TEXT, score INT, history TEXT, last_checked REAL, boost INT DEFAULT 0);
CREATE TABLE IF NOT EXISTS notes(id INTEGER PRIMARY KEY, user_id INT, msg TEXT, is_read INT DEFAULT 0, ts REAL);
CREATE TABLE IF NOT EXISTS complaints(id INTEGER PRIMARY KEY, user_id INT, url TEXT, host TEXT, type TEXT, text TEXT,
  status TEXT DEFAULT 'Open', reply TEXT DEFAULT '', ts REAL, authority TEXT DEFAULT '');
CREATE TABLE IF NOT EXISTS reviews(id INTEGER PRIMARY KEY, user_id INT, host TEXT, url TEXT, verdict TEXT, text TEXT, ts REAL);
"""


def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_):
    d = g.pop("db", None)
    if d:
        d.close()


def init_db():
    c = sqlite3.connect(DB_PATH)
    c.executescript(SCHEMA)
    try:  # upgrade older databases
        c.execute("ALTER TABLE complaints ADD COLUMN authority TEXT DEFAULT ''")
    except sqlite3.OperationalError:
        pass
    c.execute("UPDATE users SET role='government' WHERE role='advertiser'")
    c.commit()
    c.close()


def rows(q, a=()):
    return [dict(r) for r in db().execute(q, a).fetchall()]


def login_required(f):
    @wraps(f)
    def w(*a, **k):
        if "uid" not in session:
            return jsonify(error="Please log in first."), 401
        return f(*a, **k)
    return w


AUTHORITIES = [
    "Consumer Affairs (National Consumer Helpline 1915)",
    "Cyber Crime Cell (helpline 1930)",
    "RBI (financial fraud / Sachet)",
]


def gov_only(f):
    @wraps(f)
    def w(*a, **k):
        if session.get("role") != "government":
            return jsonify(error="Only government officers can do this."), 403
        return f(*a, **k)
    return w


def notify(conn, uid, msg):
    conn.execute("INSERT INTO notes(user_id,msg,ts) VALUES(?,?,?)", (uid, msg, time.time()))


def community(conn, host):
    revs = [r["verdict"] for r in conn.execute("SELECT verdict FROM reviews WHERE host=?", (host,))]
    oc = conn.execute("SELECT COUNT(*) FROM complaints WHERE host=? AND status='Open'", (host,)).fetchone()[0]
    return revs, oc


# ------------------------------------------------------------------ pages
@app.route("/")
def index():
    return render_template("index.html", authorities=AUTHORITIES)


@app.get("/samples/<path:name>")
def samples(name):
    return send_from_directory(os.path.join(BASE, "samples"), name)


# ------------------------------------------------------------------ auth
@app.post("/api/auth")
def auth():
    d = request.get_json(silent=True) or {}
    email, pw = (d.get("email") or "").strip().lower(), d.get("password") or ""
    if not re.fullmatch(r"\S+@\S+\.\S+", email) or len(pw) < 6:
        return jsonify(error="Enter a valid email and a password of at least 6 characters."), 400
    u = db().execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
    if u:
        if not check_password_hash(u["pw"], pw):
            return jsonify(error="Wrong password for this email."), 401
    else:
        role = "government" if d.get("role") == "government" else "user"
        cur = db().execute("INSERT INTO users(email,pw,role,created) VALUES(?,?,?,?)",
                           (email, generate_password_hash(pw), role, time.time()))
        db().commit()
        u = db().execute("SELECT * FROM users WHERE id=?", (cur.lastrowid,)).fetchone()
    session.clear()
    session.update(uid=u["id"], role=u["role"], email=u["email"])
    return jsonify(email=u["email"], role=u["role"])


@app.post("/api/logout")
def logout():
    session.clear()
    return jsonify(ok=True)


@app.get("/api/me")
def me():
    if "uid" not in session:
        return jsonify(user=None)
    unread = db().execute("SELECT COUNT(*) FROM notes WHERE user_id=? AND is_read=0", (session["uid"],)).fetchone()[0]
    return jsonify(user={"email": session["email"], "role": session["role"]}, unread=unread)


# ------------------------------------------------------------------ check
def run_analysis(conn, url, ad, page_input, boost=0):
    h = analyzer.host_of(url)
    revs, oc = community(conn, h)
    return analyzer.analyze(url, ad, page_input, boost, revs, oc), len(revs)


@app.post("/api/check")
@login_required
def check():
    d = request.get_json(silent=True) or {}
    url = (d.get("url") or "").strip()[:2000]
    if not url:
        return jsonify(error="Paste a link first."), 400
    r, nrev = run_analysis(db(), url, (d.get("ad_text") or "")[:3000], (d.get("page_input") or None))
    db().execute("INSERT INTO checks(user_id,url,host,score,label,risk,ts) VALUES(?,?,?,?,?,?,?)",
                 (session["uid"], url, r["host"], r["score"], r["label"], r["risk"], time.time()))
    db().commit()
    r["reviews"] = nrev
    return jsonify(r)


@app.get("/api/history")
@login_required
def history():
    return jsonify(rows("SELECT url,host,score,label,risk,ts FROM checks WHERE user_id=? ORDER BY id DESC LIMIT 20", (session["uid"],)))


# ------------------------------------------------------------------ watchlist
def recheck(conn, w, force_boost=0):
    """Re-run analysis for one watch row, notify on meaningful change."""
    boost = (w["boost"] or 0) + force_boost
    r = analyzer.analyze(w["url"], w["ad_text"] or "", w["page_input"] or None, boost, *community(conn, w["host"]))
    hist = json.loads(w["history"]) + [r["score"]]
    prev = w["label"]
    if prev == "Not suggested" and r["label"] in ("Good", "Excellent"):
        notify(conn, w["user_id"], f"{w['host']} is now rated {r['label']} ({r['score']}/100). It was 'Not suggested' earlier.")
    elif prev in ("Good", "Excellent") and r["label"] == "Not suggested":
        notify(conn, w["user_id"], f"Warning: {w['host']} dropped to 'Not suggested' ({r['score']}/100).")
    conn.execute("UPDATE watch SET label=?,score=?,history=?,last_checked=?,boost=? WHERE id=?",
                 (r["label"], r["score"], json.dumps(hist[-15:]), time.time(), boost, w["id"]))
    conn.commit()


@app.post("/api/watch")
@login_required
def watch_add():
    d = request.get_json(silent=True) or {}
    url = (d.get("url") or "").strip()
    if not analyzer.host_of(url):
        return jsonify(error="Invalid link."), 400
    if db().execute("SELECT 1 FROM watch WHERE user_id=? AND url=?", (session["uid"], url)).fetchone():
        return jsonify(error="Already on your watchlist."), 409
    r, _ = run_analysis(db(), url, d.get("ad_text") or "", d.get("page_input") or None)
    db().execute("INSERT INTO watch(user_id,url,host,ad_text,page_input,label,score,history,last_checked) VALUES(?,?,?,?,?,?,?,?,?)",
                 (session["uid"], url, r["host"], (d.get("ad_text") or "")[:3000], d.get("page_input") or None,
                  r["label"], r["score"], json.dumps([r["score"]]), time.time()))
    db().commit()
    return jsonify(ok=True)


@app.get("/api/watch")
@login_required
def watch_list():
    out = rows("SELECT id,url,host,label,score,history,last_checked FROM watch WHERE user_id=? ORDER BY id DESC", (session["uid"],))
    for o in out:
        o["history"] = json.loads(o["history"])
    return jsonify(out)


def own_watch(wid):
    return db().execute("SELECT * FROM watch WHERE id=? AND user_id=?", (wid, session["uid"])).fetchone()


@app.post("/api/watch/<int:wid>/recheck")
@login_required
def watch_recheck(wid):
    w = own_watch(wid)
    if not w:
        return jsonify(error="Not found."), 404
    demo = 40 if (request.get_json(silent=True) or {}).get("demo") else 0
    recheck(db(), w, demo)
    return jsonify(ok=True)


@app.delete("/api/watch/<int:wid>")
@login_required
def watch_del(wid):
    db().execute("DELETE FROM watch WHERE id=? AND user_id=?", (wid, session["uid"]))
    db().commit()
    return jsonify(ok=True)


def background_loop():
    """Every 10 minutes, re-check watch items not checked for 24 hours."""
    while True:
        time.sleep(600)
        try:
            conn = sqlite3.connect(DB_PATH)
            conn.row_factory = sqlite3.Row
            for w in conn.execute("SELECT * FROM watch WHERE last_checked < ?", (time.time() - RECHECK_SECONDS,)).fetchall():
                recheck(conn, w)
            conn.close()
        except Exception as e:
            print("background re-check error:", e)


# ------------------------------------------------------------------ notifications
@app.get("/api/notes")
@login_required
def notes_list():
    out = rows("SELECT id,msg,is_read,ts FROM notes WHERE user_id=? ORDER BY id DESC LIMIT 50", (session["uid"],))
    db().execute("UPDATE notes SET is_read=1 WHERE user_id=?", (session["uid"],))
    db().commit()
    return jsonify(out)


# ------------------------------------------------------------------ complaints
@app.get("/api/complaints")
@login_required
def comp_list():
    if session["role"] == "government":
        q = rows("SELECT c.*, u.email AS who FROM complaints c JOIN users u ON u.id=c.user_id ORDER BY c.id DESC")
    else:
        q = rows("SELECT * FROM complaints WHERE user_id=? ORDER BY id DESC", (session["uid"],))
    return jsonify(q)


@app.post("/api/complaints")
@login_required
def comp_add():
    d = request.get_json(silent=True) or {}
    url, text = (d.get("url") or "").strip(), (d.get("text") or "").strip()
    if not analyzer.host_of(url) or len(text) < 5:
        return jsonify(error="Add a valid link and describe the problem."), 400
    authority = d.get("authority") if d.get("authority") in AUTHORITIES else AUTHORITIES[0]
    issue = (d.get("type") or "").strip()[:120] or "Other"  # free text written by the user
    db().execute("INSERT INTO complaints(user_id,url,host,type,text,ts,authority) VALUES(?,?,?,?,?,?,?)",
                 (session["uid"], url[:2000], analyzer.host_of(url), issue, text[:2000], time.time(), authority))
    db().commit()
    return jsonify(ok=True)


@app.post("/api/complaints/<int:cid>/resolve")
@login_required
@gov_only
def comp_resolve(cid):
    c = db().execute("SELECT * FROM complaints WHERE id=?", (cid,)).fetchone()
    if not c:
        return jsonify(error="Not found."), 404
    d = request.get_json(silent=True) or {}
    status = "Under review" if d.get("status") == "Under review" else "Resolved"
    reply = (d.get("reply") or ("Your complaint is being reviewed." if status == "Under review" else "Action has been taken."))[:1000]
    db().execute("UPDATE complaints SET status=?, reply=? WHERE id=?", (status, reply, cid))
    notify(db(), c["user_id"], f"{c['authority'] or 'The government desk'} marked your complaint about {c['host']} as {status}: {reply}")
    db().commit()
    return jsonify(ok=True)


# ------------------------------------------------------------------ reviews
@app.get("/api/reviews")
@login_required
def rev_list():
    q = (request.args.get("host") or "").strip().lower()
    if q:
        return jsonify(rows("SELECT host,verdict,text,ts FROM reviews WHERE host LIKE ? ORDER BY id DESC LIMIT 50", (f"%{q}%",)))
    return jsonify(rows("SELECT host,verdict,text,ts FROM reviews ORDER BY id DESC LIMIT 50"))


@app.post("/api/reviews")
@login_required
def rev_add():
    d = request.get_json(silent=True) or {}
    url, text = (d.get("url") or "").strip(), (d.get("text") or "").strip()
    if not analyzer.host_of(url) or len(text) < 5:
        return jsonify(error="Add a valid link and a short review."), 400
    verdict = "Genuine" if d.get("verdict") == "Genuine" else "Misleading"
    db().execute("INSERT INTO reviews(user_id,host,url,verdict,text,ts) VALUES(?,?,?,?,?,?)",
                 (session["uid"], analyzer.host_of(url), url[:2000], verdict, text[:2000], time.time()))
    db().commit()
    return jsonify(ok=True)


init_db()  # make sure tables exist however the app is started

if __name__ == "__main__":
    threading.Thread(target=background_loop, daemon=True).start()
    print("TrueClick running at http://127.0.0.1:5000 | LLM:", "ON" if os.getenv("ANTHROPIC_API_KEY") else "OFF (rule-based mode)")
    app.run(host="127.0.0.1", debug=False, port=5000, use_reloader=False)
