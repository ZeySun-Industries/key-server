from flask import Flask, request, jsonify
import hashlib, time, json, secrets

app = Flask(__name__)

DB_FILE = "licenses.json"

def load_db():
    try:
        with open(DB_FILE, "r") as f:
            return json.load(f)
    except:
        return {}

def save_db(db):
    with open(DB_FILE, "w") as f:
        json.dump(db, f)

@app.route("/")
def home():
    return "Serveur de clés OK"

@app.route("/verify", methods=["POST"])
def verify():
    data = request.json
    key = data.get("key")
    hwid = data.get("hwid")

    db = load_db()

    if key not in db:
        return jsonify({"status": "invalid", "message": "Clé inconnue"})

    entry = db[key]
    if entry["hwid"] != hwid:
        return jsonify({"status": "invalid", "message": "Clé liée à un autre PC"})

    if time.time() > entry["expire"]:
        return jsonify({"status": "expired", "message": "Clé expirée"})

    return jsonify({"status": "valid", "message": "OK"})

@app.route("/generate", methods=["POST"])
def generate():
    data = request.json
    secret = data.get("secret")
    if secret != "TonMotDePasseSecret":
        return jsonify({"status": "error", "message": "Accès refusé"})

    hwid = data.get("hwid")
    duree = data.get("duree")
    expire = int(time.time()) + (duree * 86400)
    uid = secrets.token_hex(4).upper()
    key = f"LIC-{uid}-{expire}"

    db = load_db()
    db[key] = {"hwid": hwid, "expire": expire}
    save_db(db)

    return jsonify({"status": "ok", "key": key})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000)
