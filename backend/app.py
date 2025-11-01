from flask import Flask, render_template, request, jsonify, redirect, url_for
import mysql.connector
import os
import re
import json
from datetime import datetime
from collections import Counter

app = Flask(__name__, template_folder="static")

# ========== DATABASE CONNECTION ==========
try:
    db = mysql.connector.connect(
        host="localhost",
        user="root",
        password="Divesh@123",  # Replace with your password
        database="logx_db"
    )
    cursor = db.cursor()
    print("✅ Connected to MySQL and ensured database exists.")
except mysql.connector.Error as err:
    print(f"❌ MySQL Connection Failed: {err}")

# ========== DIRECTORIES ==========
UPLOAD_FOLDER = "uploads"
REPORT_FOLDER = "reports"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(REPORT_FOLDER, exist_ok=True)

# ========== INDEX ROUTE ==========
@app.route("/")
def index():
    return render_template("index.html")

# ========== UPLOAD ROUTE ==========
@app.route("/upload", methods=["POST"])
def upload_logs():
    log_type = request.form.get("log_type", "custom")
    pasted_logs = request.form.get("pasted_logs")

    # Case 1 — File uploaded
    if 'file' in request.files and request.files['file'].filename != '':
        file = request.files['file']
        filename = file.filename
        filepath = os.path.join(UPLOAD_FOLDER, filename)
        file.save(filepath)
        with open(filepath, "r", errors='ignore') as f:
            log_data = f.read()
    # Case 2 — Logs pasted manually
    elif pasted_logs:
        filename = f"pasted_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        filepath = os.path.join(UPLOAD_FOLDER, filename)
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(pasted_logs)
        log_data = pasted_logs
    else:
        return jsonify({"error": "No log data provided"}), 400

    # Store in MySQL
    cursor.execute(
        "INSERT INTO logs (filename, log_content, log_type) VALUES (%s, %s, %s)",
        (filename, log_data, log_type)
    )
    db.commit()

    # Analyze logs immediately
    result = analyze_logs(log_data, log_type)

    # Save JSON report
    report_path = os.path.join(REPORT_FOLDER, f"{filename}.json")
    with open(report_path, "w") as f:
        json.dump(result, f, indent=4)

    # Redirect to result page (Flask redirect returns 302 with URL)
    return redirect(url_for("result_page", filename=filename))

# ========== RESULT ROUTE ==========
@app.route("/result/<filename>")
def result_page(filename):
    report_path = os.path.join(REPORT_FOLDER, f"{filename}.json")
    if not os.path.exists(report_path):
        return jsonify({"error": "Report not found"}), 404
    with open(report_path, "r") as f:
        result = json.load(f)
    return render_template("result.html", result=result)

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

# ======= SPECIFIC ANALYSIS FUNCTIONS =======
def analyze_system_logs(content):
    boots = len(re.findall(r"boot", content, re.IGNORECASE))
    shutdowns = len(re.findall(r"shutdown", content, re.IGNORECASE))
    kernel = len(re.findall(r"kernel", content, re.IGNORECASE))
    return {
        "system_boots": boots,
        "system_shutdowns": shutdowns,
        "kernel_events": kernel
    }

def analyze_server_logs(content):
    methods = re.findall(r"\b(GET|POST|PUT|DELETE|PATCH|OPTIONS)\b", content)
    endpoints = re.findall(r"\"(GET|POST|PUT|DELETE|PATCH|OPTIONS) (.*?) HTTP", content)
    return {
        "http_methods_count": dict(Counter(methods)),
        "top_endpoints": dict(Counter([e[1] for e in endpoints]).most_common(5))
    }

def analyze_custom_logs(content):
    kv_pairs = re.findall(r"(\w+)=([\w\d\._-]+)", content)
    return {
        "key_value_pairs_found": len(kv_pairs),
        "sample_pairs": kv_pairs[:5]
    }

# ========== MAIN ==========
if __name__ == "__main__":
    app.run(debug=True)
