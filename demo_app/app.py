"""
MedSecure Demo Application
A deliberately vulnerable Flask app for demonstrating SecureFlow's
automated security remediation pipeline with CodeQL + Devin.
"""

import os
import sqlite3
from flask import Flask, request, jsonify, send_file

app = Flask(__name__)

# --- CWE-798: Hardcoded Credentials ---
DATABASE_PASSWORD = "super_secret_password_123"
API_KEY = "sk-live-abc123def456ghi789"
ADMIN_TOKEN = "admin-token-do-not-share-9876"

DB_PATH = os.path.join(os.path.dirname(__file__), "app.db")


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    conn.execute(
        "CREATE TABLE IF NOT EXISTS users "
        "(id INTEGER PRIMARY KEY, username TEXT, email TEXT, role TEXT)"
    )
    conn.execute(
        "CREATE TABLE IF NOT EXISTS transactions "
        "(id INTEGER PRIMARY KEY, from_account TEXT, to_account TEXT, amount REAL)"
    )
    conn.commit()
    conn.close()


@app.route("/")
def index():
    return jsonify({"status": "ok", "app": "MedSecure Demo"})


# --- CWE-89: SQL Injection ---
@app.route("/users")
def get_user():
    username = request.args.get("username", "")
    conn = get_db()
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor = conn.execute(query)
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return jsonify(rows)


@app.route("/users/search")
def search_users():
    role = request.args.get("role", "")
    conn = get_db()
    query = "SELECT * FROM users WHERE role = '" + role + "'"
    cursor = conn.execute(query)
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return jsonify(rows)


# --- CWE-79: Cross-Site Scripting (XSS) ---
@app.route("/search")
def search():
    q = request.args.get("q", "")
    return f"<h1>Search Results for: {q}</h1><p>No results found.</p>"


@app.route("/greet")
def greet():
    name = request.args.get("name", "Guest")
    return f"<html><body><h2>Welcome, {name}!</h2></body></html>"


# --- CWE-22: Path Traversal ---
@app.route("/files/<path:filename>")
def get_file(filename):
    file_path = os.path.join("/data/reports", filename)
    return send_file(file_path)


@app.route("/download")
def download():
    doc = request.args.get("doc", "")
    return send_file(os.path.join("/data/documents", doc))


# --- CWE-78: Command Injection ---
@app.route("/ping")
def ping():
    host = request.args.get("host", "")
    result = os.popen(f"ping -c 1 {host}").read()
    return f"<pre>{result}</pre>"


@app.route("/dns")
def dns_lookup():
    domain = request.args.get("domain", "")
    result = os.popen("nslookup " + domain).read()
    return jsonify({"result": result})


# --- CWE-20: Missing Input Validation ---
@app.route("/transfer", methods=["POST"])
def transfer():
    data = request.get_json()
    amount = data.get("amount")
    to_account = data.get("to")
    from_account = data.get("from")

    conn = get_db()
    conn.execute(
        "INSERT INTO transactions (from_account, to_account, amount) VALUES (?, ?, ?)",
        (from_account, to_account, amount),
    )
    conn.commit()
    conn.close()

    return jsonify({"status": "ok", "transferred": amount})


@app.route("/set-role", methods=["POST"])
def set_role():
    data = request.get_json()
    user_id = data.get("user_id")
    role = data.get("role")
    conn = get_db()
    conn.execute(f"UPDATE users SET role = '{role}' WHERE id = {user_id}")
    conn.commit()
    conn.close()
    return jsonify({"status": "updated"})


if __name__ == "__main__":
    init_db()
    app.run(debug=True, port=5001)
