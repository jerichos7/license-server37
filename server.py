import os
import sqlite3
import time
import threading
from datetime import datetime, timezone
from flask import Flask, request, jsonify
from flask_socketio import SocketIO, emit, join_room
import jwt

JWT_SECRET = os.environ.get("JWT_SECRET", "dev-secret")
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "dev-admin")
DB_PATH = os.environ.get("DB_PATH", "licenses.db")
EXPIRE_CHECK_INTERVAL = 10

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("FLASK_SECRET", "flask-secret")
socketio = SocketIO(app, cors_allowed_origins="*")

def db_conn():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = db_conn()
    conn.execute("""
    CREATE TABLE IF NOT EXISTS licenses (
        username TEXT PRIMARY KEY,
        password_hash TEXT NOT NULL,
        expire_ts INTEGER NOT NULL,
        hwid_lock TEXT,
        active INTEGER NOT NULL DEFAULT 1
    )
    """)
    conn.commit(); conn.close()

def now_ts():
    return int(datetime.now(timezone.utc).timestamp())

@app.get("/")
def health():
    return jsonify(ok=True, ts=now_ts())

def require_admin(req):
    tok = req.headers.get("Authorization", "").replace("Bearer ", "").strip()
    return tok and tok == ADMIN_TOKEN

@app.post("/admin/add_license")
def admin_add():
    if not require_admin(request):
        return jsonify(ok=False, err="unauthorized"), 401
    data = request.get_json(force=True) or {}
    username = data.get("username")
    password_hash = data.get("password_hash")
    expire_date = data.get("expire_date")
    hwid_lock = data.get("hwid_lock")
    active = 1 if data.get("active", True) else 0
    if not username or not password_hash or not expire_date:
        return jsonify(ok=False, err="missing_fields"), 400
    try:
        dt = datetime.fromisoformat(expire_date)
        exp_ts = int(dt.replace(tzinfo=timezone.utc).timestamp())
    except Exception:
        return jsonify(ok=False, err="bad_expire_date"), 400
    conn = db_conn()
    conn.execute("REPLACE INTO licenses(username, password_hash, expire_ts, hwid_lock, active) VALUES(?,?,?,?,?)",
                 (username, password_hash, exp_ts, hwid_lock, active))
    conn.commit(); conn.close()
    return jsonify(ok=True)

@app.post("/admin/revoke")
def admin_revoke():
    if not require_admin(request):
        return jsonify(ok=False, err="unauthorized"), 401
    data = request.get_json(force=True) or {}
    username = data.get("username")
    if not username:
        return jsonify(ok=False, err="missing_username"), 400
    conn = db_conn()
    conn.execute("UPDATE licenses SET active=0 WHERE username=?", (username,))
    conn.commit(); conn.close()
    socketio.emit("revoked", {"username": username}, room=f"user:{username}")
    return jsonify(ok=True)

@app.post("/admin/reset_hwid")
def admin_reset_hwid():
    if not require_admin(request):
        return jsonify(ok=False, err="unauthorized"), 401
    data = request.get_json(force=True) or {}
    username = data.get("username")
    if not username:
        return jsonify(ok=False, err="missing_username"), 400
    conn = db_conn()
    conn.execute("UPDATE licenses SET hwid_lock=NULL WHERE username=?", (username,))
    conn.commit(); conn.close()
    return jsonify(ok=True)

@app.post("/auth")
def auth():
    data = request.get_json(force=True) or {}
    username = data.get("username")
    password = data.get("password")
    hwid = data.get("hwid")
    if not username or not password:
        return jsonify(ok=False, err="missing_creds"), 400
    conn = db_conn()
    row = conn.execute("SELECT password_hash, expire_ts, hwid_lock, active FROM licenses WHERE username=?",
                       (username,)).fetchone()
    conn.close()
    if not row:
        return jsonify(ok=False, err="not_found"), 404
    if row["active"] != 1:
        return jsonify(ok=False, err="inactive"), 403
    if row["password_hash"] != password:
        return jsonify(ok=False, err="bad_password"), 403
    if row["expire_ts"] < now_ts():
        return jsonify(ok=False, err="expired"), 403
    if row["hwid_lock"] and hwid and row["hwid_lock"] != hwid:
        return jsonify(ok=False, err="hwid_mismatch"), 403
    payload = {"sub": username, "exp": now_ts() + 3600*12}
    token = jwt.encode(payload, JWT_SECRET, algorithm="HS256")
    return jsonify(ok=True, token=token)

@socketio.on("connect")
def on_connect():
    try:
        environ = request.environ
        authz = environ.get("HTTP_AUTHORIZATION", "")
        token = authz.replace("Bearer ", "").strip()
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        username = payload["sub"]
    except Exception:
        return False
    conn = db_conn()
    row = conn.execute("SELECT active, expire_ts FROM licenses WHERE username=?", (username,)).fetchone()
    conn.close()
    if not row or row["active"] != 1 or row["expire_ts"] < now_ts():
        return False
    join_room(f"user:{username}")
    emit("ok", {"msg":"connected","user":username})

def expire_watcher():
    while True:
        try:
            ts = now_ts()
            conn = db_conn()
            rows = conn.execute("SELECT username FROM licenses WHERE expire_ts <= ? AND active=1", (ts,)).fetchall()
            for r in rows:
                u = r["username"]
                conn.execute("UPDATE licenses SET active=0 WHERE username=?", (u,))
                socketio.emit("expired", {"username": u}, room=f"user:{u}")
            conn.commit(); conn.close()
        except Exception as e:
            print("expire_watcher error:", e)
        time.sleep(EXPIRE_CHECK_INTERVAL)

threading.Thread(target=expire_watcher, daemon=True).start()
init_db()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    socketio.run(app, host="0.0.0.0", port=port)
