from flask import Flask, request, jsonify, send_from_directory, abort
import os, json, uuid, hashlib
from datetime import datetime

app = Flask(__name__, static_folder="static")
SCRIPTS_DIR = "scripts"
os.makedirs(SCRIPTS_DIR, exist_ok=True)

def hash_password(pw):
    return hashlib.sha256(pw.encode()).hexdigest() if pw else None

def load_meta(sid):
    path = os.path.join(SCRIPTS_DIR, sid + ".json")
    if not os.path.exists(path):
        return None
    with open(path) as f:
        return json.load(f)

def save_meta(sid, meta):
    with open(os.path.join(SCRIPTS_DIR, sid + ".json"), "w") as f:
        json.dump(meta, f)

def save_script(sid, content):
    with open(os.path.join(SCRIPTS_DIR, sid + ".lua"), "w") as f:
        f.write(content)

def load_script(sid):
    path = os.path.join(SCRIPTS_DIR, sid + ".lua")
    if not os.path.exists(path):
        return None
    with open(path) as f:
        return f.read()

def build_anti_skid_file(sid, lua_code):
    view_url = f"/view/{sid}"
    html_block = f"""--[[
<html>
<head>
  <meta charset="UTF-8">
  <meta http-equiv="refresh" content="0; url={view_url}">
  <style>
    body {{ background: #050508; margin: 0; display: flex; align-items: center; justify-content: center; height: 100vh; }}
    p {{ color: #7c3aed; font-family: monospace; font-size: 16px; }}
  </style>
</head>
<body><p>Access denied. Redirecting...</p></body>
</html>
]]
"""
    return html_block + lua_code

@app.route("/")
def index():
    return send_from_directory("static", "index.html")

@app.route("/view/<sid>")
def view_page(sid):
    meta = load_meta(sid)
    if not meta:
        abort(404)
    if meta.get("anti_skid"):
        content = load_script(sid)
        if content is None:
            abort(404)
        return content, 200, {"Content-Type": "text/plain; charset=utf-8"}
    return send_from_directory("static", "view.html")

@app.route("/api/upload", methods=["POST"])
def upload():
    data = request.json
    code = data.get("code", "").strip()
    password = data.get("password", "").strip()
    title = data.get("title", "Untitled Script").strip()
    anti_skid = bool(data.get("anti_skid", False))
    if not code:
        return jsonify({"error": "No code provided"}), 400
    sid = uuid.uuid4().hex[:10]
    meta = {
        "id": sid,
        "title": title,
        "password_hash": hash_password(password) if password else None,
        "anti_skid": anti_skid,
        "created": datetime.utcnow().isoformat(),
    }
    save_meta(sid, meta)
    if anti_skid:
        save_script(sid, build_anti_skid_file(sid, code))
    else:
        save_script(sid, code)
    result = {"id": sid, "view_url": f"/view/{sid}"}
    if not anti_skid:
        result["raw_url"] = f"/raw/{sid}"
    return jsonify(result)

@app.route("/raw/<sid>")
def raw_script(sid):
    meta = load_meta(sid)
    if not meta:
        abort(404)
    if meta.get("anti_skid"):
        abort(404)
    content = load_script(sid)
    if content is None:
        abort(404)
    return content, 200, {"Content-Type": "text/plain; charset=utf-8"}

@app.route("/api/meta/<sid>")
def get_meta(sid):
    meta = load_meta(sid)
    if not meta:
        return jsonify({"error": "Not found"}), 404
    return jsonify({
        "id": meta["id"],
        "title": meta["title"],
        "has_password": bool(meta.get("password_hash")),
        "anti_skid": bool(meta.get("anti_skid")),
        "created": meta["created"],
    })

@app.route("/api/get_code/<sid>", methods=["POST"])
def get_code(sid):
    meta = load_meta(sid)
    if not meta:
        return jsonify({"error": "Not found"}), 404
    if meta.get("password_hash"):
        pw = request.json.get("password", "")
        if hash_password(pw) != meta["password_hash"]:
            return jsonify({"error": "Wrong password"}), 403
    content = load_script(sid)
    if content and meta.get("anti_skid") and "]]" in content:
        lua_only = content[content.index("]]") + 2:].lstrip("\n")
    else:
        lua_only = content or ""
    return jsonify({"code": lua_only, "title": meta["title"]})

@app.route("/api/update/<sid>", methods=["POST"])
def update_script(sid):
    meta = load_meta(sid)
    if not meta:
        return jsonify({"error": "Not found"}), 404
    if not meta.get("password_hash"):
        return jsonify({"error": "Access denied — this script has no password and cannot be modified"}), 403
    pw = request.json.get("password", "")
    if hash_password(pw) != meta["password_hash"]:
        return jsonify({"error": "Wrong password"}), 403
    code = request.json.get("code", "").strip()
    title = request.json.get("title", meta["title"]).strip()
    if not code:
        return jsonify({"error": "No code"}), 400
    meta["title"] = title
    save_meta(sid, meta)
    if meta.get("anti_skid"):
        save_script(sid, build_anti_skid_file(meta["id"], code))
    else:
        save_script(sid, code)
    return jsonify({"ok": True})

@app.route("/api/delete/<sid>", methods=["POST"])
def delete_script(sid):
    meta = load_meta(sid)
    if not meta:
        return jsonify({"error": "Not found"}), 404
    if not meta.get("password_hash"):
        return jsonify({"error": "Access denied — this script has no password and cannot be deleted"}), 403
    pw = request.json.get("password", "")
    if hash_password(pw) != meta["password_hash"]:
        return jsonify({"error": "Wrong password"}), 403
    os.remove(os.path.join(SCRIPTS_DIR, sid + ".lua"))
    os.remove(os.path.join(SCRIPTS_DIR, sid + ".json"))
    return jsonify({"ok": True})

if __name__ == "__main__":
    app.run(debug=True, port=5000)
