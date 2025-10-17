import os, requests

BASE = os.environ.get("BASE") or os.environ.get("LIC_SERVER") or "http://127.0.0.1:5000"
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "dev-admin")

def _post(path, payload):
    r = requests.post(f"{BASE}{path}", json=payload, headers={"Authorization": f"Bearer {ADMIN_TOKEN}"}, timeout=10)
    try:
        j = r.json()
    except Exception:
        j = {"text": r.text}
    print(r.status_code, j)
    return j

def add(username, password_hash, expire_iso, hwid_lock=None, active=True):
    return _post("/admin/add_license", {
        "username": username,
        "password_hash": password_hash,
        "expire_date": expire_iso,
        "hwid_lock": hwid_lock,
        "active": active
    })

def revoke(username):
    return _post("/admin/revoke", {"username": username})

def reset_hwid(username):
    return _post("/admin/reset_hwid", {"username": username})
