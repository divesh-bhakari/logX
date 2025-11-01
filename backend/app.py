from flask import Flask, render_template, request, jsonify, redirect, url_for, session
import mysql.connector
import os
import re
import json
from datetime import datetime
from collections import Counter
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__, template_folder="static")
app.secret_key = "supersecretkey"  # required for session management

# ========== DATABASE CONNECTION ==========
try:
    db = mysql.connector.connect(
        host="localhost",
        user="root",
        password="Divesh@123",
        database="logx_db"
    )
    cursor = db.cursor(dictionary=True)
    print("✅ Connected to MySQL and ensured database exists.")
except mysql.connector.Error as err:
    print(f"❌ MySQL Connection Failed: {err}")

# ========== DIRECTORIES ==========
UPLOAD_FOLDER = "uploads"
REPORT_FOLDER = "reports"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(REPORT_FOLDER, exist_ok=True)

# ========== ROUTES ==========

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/login")
def login_page():
    return render_template("login.html")

@app.route("/register")
def register_page():
    return render_template("register.html")

@app.route("/result/<filename>")
def result_page(filename):
    report_path = os.path.join(REPORT_FOLDER, f"{filename}.json")
    if not os.path.exists(report_path):
        return jsonify({"error": "Report not found"}), 404
    with open(report_path, "r") as f:
        result = json.load(f)
    return render_template("result.html", result=result)

# ========== AUTHENTICATION ROUTES ==========

@app.route("/api/register", methods=["POST"])
def register_user():
    data = request.get_json()
    name = data.get("name")
    email = data.get("email")
    password = data.get("password")

    if not name or not email or not password:
        return jsonify({"error": "All fields required"}), 400

    cursor.execute("SELECT * FROM users WHERE email=%s", (email,))
    if cursor.fetchone():
        return jsonify({"error": "Email already registered"}), 400

    hashed_pw = generate_password_hash(password)
    cursor.execute(
        "INSERT INTO users (name, email, password) VALUES (%s, %s, %s)",
        (name, email, hashed_pw)
    )
    db.commit()
    return jsonify({"message": "Registration successful"}), 200


@app.route("/api/login", methods=["POST"])
def login_user():
    data = request.get_json()
    email = data.get("email")
    password = data.get("password")

    cursor.execute("SELECT * FROM users WHERE email=%s", (email,))
    user = cursor.fetchone()

    if not user or not check_password_hash(user["password"], password):
        return jsonify({"error": "Invalid email or password"}), 401

    session["user_id"] = user["id"]
    session["user_name"] = user["name"]
    return jsonify({"message": "Login successful"}), 200


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))

# ========== UPLOAD ROUTE ==========
@app.route("/upload", methods=["POST"])
def upload_logs():
    log_type = request.form.get("log_type", "custom")
    pasted_logs = request.form.get("pasted_logs")

    if 'file' in request.files and request.files['file'].filename != '':
        file = request.files['file']
        filename = file.filename
        filepath = os.path.join(UPLOAD_FOLDER, filename)
        file.save(filepath)
        with open(filepath, "r", errors='ignore') as f:
            log_data = f.read()
    elif pasted_logs:
        filename = f"pasted_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        filepath = os.path.join(UPLOAD_FOLDER, filename)
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(pasted_logs)
        log_data = pasted_logs
    else:
        return jsonify({"error": "No log data provided"}), 400

    cursor.execute(
        "INSERT INTO logs (filename, log_content, log_type) VALUES (%s, %s, %s)",
        (filename, log_data, log_type)
    )
    db.commit()

    result = analyze_logs(log_data, log_type)
    report_path = os.path.join(REPORT_FOLDER, f"{filename}.json")
    with open(report_path, "w") as f:
        json.dump(result, f, indent=4)

    return redirect(url_for("result_page", filename=filename))

# ========== LOG ANALYSIS ENGINE ==========
def analyze_logs(content, log_type):
    lines = content.splitlines()
    result = {
        "total_lines": len(lines),
        "errors": 0,
        "warnings": 0,
        "info": 0,
        "unique_ips": set(),
        "status_codes": [],
        "timestamps": [],
        "failed_logins": 0,
        "log_type": log_type
    }

    ip_pattern = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
    status_pattern = re.compile(r"\b\d{3}\b")
    time_pattern = re.compile(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}")
    error_pattern = re.compile(r"error", re.IGNORECASE)
    warn_pattern = re.compile(r"warn", re.IGNORECASE)
    info_pattern = re.compile(r"info", re.IGNORECASE)
    failed_pattern = re.compile(r"failed login|authentication failure", re.IGNORECASE)

    for line in lines:
        if error_pattern.search(line):
            result["errors"] += 1
        if warn_pattern.search(line):
            result["warnings"] += 1
        if info_pattern.search(line):
            result["info"] += 1

        ips = ip_pattern.findall(line)
        if ips:
            result["unique_ips"].update(ips)

        statuses = status_pattern.findall(line)
        for s in statuses:
            if s.startswith(("2", "3", "4", "5")):
                result["status_codes"].append(s)

        times = time_pattern.findall(line)
        result["timestamps"].extend(times)

        if failed_pattern.search(line):
            result["failed_logins"] += 1

    result["unique_ips"] = list(result["unique_ips"])
    result["top_status_codes"] = dict(Counter(result["status_codes"]).most_common(5))

    if log_type.lower() == "system":
        result.update(analyze_system_logs(content))
    elif log_type.lower() == "server":
        result.update(analyze_server_logs(content))
    elif log_type.lower() == "custom":
        result.update(analyze_custom_logs(content))

    return result

def analyze_system_logs(content):
    boots = len(re.findall(r"boot", content, re.IGNORECASE))
    shutdowns = len(re.findall(r"shutdown", content, re.IGNORECASE))
    kernel = len(re.findall(r"kernel", content, re.IGNORECASE))
    return {"system_boots": boots, "system_shutdowns": shutdowns, "kernel_events": kernel}

def analyze_server_logs(content):
    methods = re.findall(r"\b(GET|POST|PUT|DELETE|PATCH|OPTIONS)\b", content)
    endpoints = re.findall(r"\"(GET|POST|PUT|DELETE|PATCH|OPTIONS) (.*?) HTTP", content)
    return {"http_methods_count": dict(Counter(methods)), "top_endpoints": dict(Counter([e[1] for e in endpoints]).most_common(5))}

def analyze_custom_logs(content):
    kv_pairs = re.findall(r"(\w+)=([\w\d\._-]+)", content)
    return {"key_value_pairs_found": len(kv_pairs), "sample_pairs": kv_pairs[:5]}

# ========== MAIN ==========
if __name__ == "__main__":
    app.run(debug=True)
