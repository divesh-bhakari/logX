# app.py
from flask import Flask, render_template, request, jsonify, redirect, url_for, session, send_file
import mysql.connector
import os
import re
import json
import csv
from io import StringIO
from datetime import datetime, timedelta
from collections import Counter, defaultdict
from werkzeug.security import generate_password_hash, check_password_hash

# Optional geoip2 — used if user installs MaxMind DB and geoip2 package
try:
    import geoip2.database
    GEOIP_AVAILABLE = True
except Exception:
    GEOIP_AVAILABLE = False

app = Flask(__name__, template_folder="static")
app.secret_key = "supersecretkey"

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
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
REPORT_FOLDER = os.path.join(BASE_DIR, "reports")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(REPORT_FOLDER, exist_ok=True)

# OPTIONAL: path to MaxMind DB (if you want geo lookups). Leave None to disable.
MAXMIND_DB_PATH = os.path.join(BASE_DIR, "GeoLite2-City.mmdb")
if GEOIP_AVAILABLE and not os.path.exists(MAXMIND_DB_PATH):
    GEOIP_AVAILABLE = False  # disable if DB missing

# ----------------- ROUTES -----------------
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

# ----------------- AUTH (unchanged) -----------------
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
    cursor.execute("INSERT INTO users (name, email, password) VALUES (%s, %s, %s)", (name, email, hashed_pw))
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

# ----------------- UPLOAD -----------------
@app.route("/upload", methods=["POST"])
def upload_logs():
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

    # Save raw log to DB (log_type = auto)
    try:
        cursor.execute("INSERT INTO logs (filename, log_content, log_type) VALUES (%s, %s, %s)", (filename, log_data, "auto"))
        db.commit()
    except Exception:
        db.rollback()

    # Universal analysis
    result = analyze_logs_universal(log_data)

    # Save JSON report
    report_path = os.path.join(REPORT_FOLDER, f"{filename}.json")
    with open(report_path, "w") as f:
        json.dump(result, f, indent=2)

    return redirect(url_for("result_page", filename=filename))

# ----------------- UNIVERSAL ANALYZER -----------------
def analyze_logs_universal(content):
    """
    Enhanced universal analyzer that:
    - robust timestamp parsing (multiple formats)
    - builds timeline (minute-buckets) for charting
    - improved format detection with readable guess
    - improved security summary and attack detection
    - graceful fallbacks for UI
    """
    lines = content.splitlines()
    total_lines = len(lines)

    # containers
    ips = []
    status_codes = []
    timestamps = []      # store normalized ISO strings
    emails = set()
    urls = []
    methods = []
    endpoints = []
    user_agents = []
    file_paths = []
    kv_pairs = []
    response_times = []
    response_sizes = []
    sqli_samples = []
    xss_samples = []
    failed_by_ip = defaultdict(list)
    failed_by_user = defaultdict(list)

    # patterns (expand multiple timestamp formats)
    patterns = {
        "ip": re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"),
        "status": re.compile(r"\b([1-5][0-9]{2})\b"),
        # ISO 2020-...  and Apache common: [10/Oct/2000:13:55:36 -0700]
        "iso_time": re.compile(r"\b\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}\b"),
        "apache_time": re.compile(r"\[(\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2})\s?[+\-]?\d*\]"),
        # Nginx or CLF without brackets: 10/Oct/2000:13:55:36
        "clf_time": re.compile(r"\b\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2}\b"),
        "email": re.compile(r"[a-zA-Z0-9.\-_+%]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}"),
        "url": re.compile(r"https?://[^\s\"']+"),
        "method_endpoint": re.compile(r"\b(GET|POST|PUT|DELETE|PATCH|OPTIONS)\b\s+([^\s\"']+)"),
        "user_agent": re.compile(r'User-Agent:\s*["\']?([^"\']{10,300})', re.IGNORECASE),
        "file_path": re.compile(r"(?:[A-Za-z]:(?:\\|/)[\w\\/.:-]+)|(?:\/[\w\/.\-]+)"),
        "kv": re.compile(r"(\b[\w\.\-]+\b)=(\"?[^\s,;]+\"?)"),
        "time_ms": re.compile(r"\btime[=:\s]?([0-9]+(?:\.[0-9]+)?)ms\b", re.IGNORECASE),
        "time_s": re.compile(r"\b(?:time|latency|response_time)[=:\s]?([0-9]+(?:\.[0-9]+)?)s\b", re.IGNORECASE),
        "size_after_status": re.compile(r'\b[1-5][0-9]{2}\b[^\d]{0,3}(\d{1,7})(?:\s|$)'),
    }

    # SQLi / XSS signatures
    sqli_signatures = [
        r"(\bUNION\b.*\bSELECT\b)", r"(\bSELECT\b.*\bFROM\b)", r"(\bOR\b\s+'1'='1')",
        r"(--|\#\s*$)", r"(/\*.*\*/)", r"(\bDROP\b|\bINSERT\b|\bUPDATE\b|\bDELETE\b)", r"(%27)|(' OR ')"
    ]
    sqli_regex = [re.compile(p, re.IGNORECASE) for p in sqli_signatures]
    xss_patterns = [
        r"<script\b[^>]*>(.*?)</script>", r"onerror\s*=", r"onload\s*=", r"javascript:",
        r"<img\b[^>]*on\w+\s*=", r"%3Cscript%3E"
    ]
    xss_regex = [re.compile(p, re.IGNORECASE) for p in xss_patterns]

    failed_login_re = re.compile(r"failed login|authentication failure|login failed|invalid password|invalid credentials|unauthorized", re.IGNORECASE)
    user_re = re.compile(r"user(?:name)?[=:\s]([A-Za-z0-9@._-]+)", re.IGNORECASE)

    # robust time parsing helper
    def norm_time_to_iso(ts_str):
        # try several formats
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%d/%b/%Y:%H:%M:%S"):
            try:
                dt = datetime.strptime(ts_str, fmt)
                return dt.strftime("%Y-%m-%d %H:%M:%S")
            except Exception:
                pass
        # try parsing apache-like with month names (10/Oct/2000:13:55:36)
        try:
            if "/" in ts_str and ":" in ts_str:
                dt = datetime.strptime(ts_str, "%d/%b/%Y:%H:%M:%S")
                return dt.strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            pass
        return None

    # per-line parsing
    for i, line in enumerate(lines):
        # ips
        for ip in patterns["ip"].findall(line):
            parts = ip.split(".")
            if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
                ips.append(ip)

        # status codes
        for s in patterns["status"].findall(line):
            status_codes.append(s)

        # timestamps: try ISO, apache bracket, clf
        for t in patterns["iso_time"].findall(line):
            iso = norm_time_to_iso(t)
            if iso:
                timestamps.append(iso)
        for m in patterns["apache_time"].findall(line):
            iso = norm_time_to_iso(m)
            if iso:
                timestamps.append(iso)
        for c in patterns["clf_time"].findall(line):
            iso = norm_time_to_iso(c)
            if iso:
                timestamps.append(iso)

        # emails
        for e in patterns["email"].findall(line):
            emails.add(e)

        # urls
        for u in patterns["url"].findall(line):
            urls.append(u)

        # methods/endpoints
        for m in patterns["method_endpoint"].findall(line):
            methods.append(m[0])
            endpoints.append(m[1])

        # user agent
        ua = patterns["user_agent"].search(line)
        if ua:
            user_agents.append(ua.group(1).strip())

        # file paths
        for fp in patterns["file_path"].findall(line):
            if len(fp) > 3:
                file_paths.append(fp)

        # kv pairs
        for kv in patterns["kv"].findall(line):
            kv_pairs.append({kv[0]: kv[1].strip('"')})

        # response times
        for tm in patterns["time_ms"].findall(line):
            try:
                response_times.append(float(tm))
            except:
                pass
        for ts in patterns["time_s"].findall(line):
            try:
                response_times.append(float(ts) * 1000.0)
            except:
                pass

        # response sizes
        for sz in patterns["size_after_status"].findall(line):
            try:
                response_sizes.append(int(sz))
            except:
                pass

        # sqli/xss detection
        for rx in sqli_regex:
            if rx.search(line):
                if len(sqli_samples) < 50:
                    sqli_samples.append({"line_no": i+1, "snippet": line.strip()[:600]})
        for rx in xss_regex:
            if rx.search(line):
                if len(xss_samples) < 50:
                    xss_samples.append({"line_no": i+1, "snippet": line.strip()[:600]})

        # failed login heuristics (for bruteforce)
        if failed_login_re.search(line):
            ip_candidates = patterns["ip"].findall(line)
            ts_candidate = None
            # prefer parsed timestamp from line
            iso_ts = None
            m_iso = patterns["iso_time"].search(line)
            if m_iso:
                iso_ts = norm_time_to_iso(m_iso.group(0))
            else:
                m_ap = patterns["apache_time"].search(line)
                if m_ap:
                    iso_ts = norm_time_to_iso(m_ap.group(1))
                else:
                    m_clf = patterns["clf_time"].search(line)
                    if m_clf:
                        iso_ts = norm_time_to_iso(m_clf.group(0))
            if iso_ts:
                try:
                    ts_candidate = datetime.strptime(iso_ts, "%Y-%m-%d %H:%M:%S")
                except:
                    ts_candidate = datetime.utcnow()
            else:
                ts_candidate = datetime.utcnow()
            u = user_re.search(line)
            username = u.group(1) if u else None
            if ip_candidates:
                failed_by_ip[ip_candidates[0]].append(ts_candidate)
            if username:
                failed_by_user[username].append(ts_candidate)

    # post-processing
    errors_count = len(re.findall(r"\berror\b", content, re.IGNORECASE))
    warnings_count = len(re.findall(r"\bwarn(?:ing)?\b", content, re.IGNORECASE))
    info_count = len(re.findall(r"\binfo\b", content, re.IGNORECASE))
    failed_login_count = sum(len(v) for v in failed_by_ip.values()) or len(re.findall(failed_login_re, content))

    # brute-force detection: sliding window
    bruteforce_findings = []
    BF_THRESHOLD = 8
    BF_WINDOW_MINUTES = 5
    for ip, times in failed_by_ip.items():
        normalized = sorted(times)
        for start_idx in range(len(normalized)):
            start = normalized[start_idx]
            end = start + timedelta(minutes=BF_WINDOW_MINUTES)
            count = sum(1 for t in normalized if start <= t <= end)
            if count >= BF_THRESHOLD:
                bruteforce_findings.append({
                    "ip": ip,
                    "window_start": start.strftime("%Y-%m-%d %H:%M:%S"),
                    "attempts_in_window": count
                })
                break

    # timeline: bucket timestamps by minute for charting
    timeline = {}
    if timestamps:
        for ts in timestamps:
            # ts already normalized as "YYYY-MM-DD HH:MM:SS"
            try:
                dt = datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")
                key = dt.strftime("%Y-%m-%d %H:%M")  # minute bucket
                timeline[key] = timeline.get(key, 0) + 1
            except:
                pass

    # assemble output, include only present fields
    out = {"total_lines": total_lines}

    if errors_count: out["errors"] = errors_count
    if warnings_count: out["warnings"] = warnings_count
    if info_count: out["info"] = info_count
    if failed_login_count: out["failed_logins"] = failed_login_count

    if ips:
        unique_ips = sorted(set(ips))
        out["unique_ips"] = unique_ips
        out["top_ips"] = dict(Counter(ips).most_common(10))

    if status_codes:
        out["status_codes_raw"] = status_codes
        out["top_status_codes"] = dict(Counter(status_codes).most_common(10))

    if timestamps:
        out["timestamps_sample"] = sorted(list({t for t in timestamps}))[:200]
        # timeline as sorted list of {bucket, count}
        out["timeline"] = [{"bucket": k, "count": v} for k, v in sorted(timeline.items())]

    if emails:
        out["emails"] = sorted(list(emails))

    if urls:
        out["urls_sample"] = list(dict.fromkeys(urls))[:200]

    if methods:
        out["http_methods_count"] = dict(Counter(methods).most_common())

    if endpoints:
        out["top_endpoints"] = dict(Counter(endpoints).most_common(30))
    else:
        # graceful fallback so frontend won't show an empty table
        out["top_endpoints"] = {"No endpoints found": 0}

    if user_agents:
        out["user_agents_sample"] = user_agents[:50]

    if file_paths:
        out["file_paths_sample"] = list(dict.fromkeys(file_paths))[:50]

    if kv_pairs:
        out["key_value_pairs_count"] = len(kv_pairs)
        out["key_value_pairs_sample"] = kv_pairs[:50]

    if response_times:
        rt_ms = [float(x) for x in response_times if isinstance(x, (int, float))]
        if rt_ms:
            out["response_time_ms"] = {
                "count": len(rt_ms),
                "min_ms": min(rt_ms),
                "max_ms": max(rt_ms),
                "avg_ms": sum(rt_ms) / len(rt_ms),
                "p50_ms": percentile(rt_ms, 50),
                "p95_ms": percentile(rt_ms, 95)
            }

    if response_sizes:
        rs = [int(x) for x in response_sizes if isinstance(x, int)]
        if rs:
            out["response_size_bytes"] = {
                "count": len(rs),
                "min": min(rs),
                "max": max(rs),
                "avg": sum(rs) / len(rs)
            }

    # Attack detectors
    attack_summary = {}
    if bruteforce_findings:
        attack_summary["bruteforce"] = bruteforce_findings
    if sqli_samples:
        attack_summary["sql_injection_samples"] = sqli_samples
        attack_summary["sql_injection_count"] = len(sqli_samples)
    if xss_samples:
        attack_summary["xss_samples"] = xss_samples
        attack_summary["xss_count"] = len(xss_samples)
    if attack_summary:
        out["attack_summary"] = attack_summary

    # Security summary + risk scoring (0-100)
    risk_score, risk_messages = compute_risk_and_messages(
        errors_count, warnings_count, failed_login_count,
        len(sqli_samples), len(xss_samples), len(bruteforce_findings), total_lines
    )
    out["security_summary"] = {
        "risk_score": risk_score,
        "messages": risk_messages
    }

    # Log format heuristics (friendly names)
    format_candidates = detect_log_formats(content, out)
    if format_candidates:
        out["format_candidates"] = format_candidates
        out["format_guess"] = format_candidates[0]
    else:
        out["format_guess"] = "unknown"

    # optional geo
    if GEOIP_AVAILABLE and out.get("top_ips"):
        try:
            reader = geoip2.database.Reader(MAXMIND_DB_PATH)
            geo = {}
            for ip, _ in out["top_ips"].items():
                try:
                    rec = reader.city(ip)
                    geo[ip] = {
                        "country": rec.country.name,
                        "city": rec.city.name,
                        "latitude": rec.location.latitude,
                        "longitude": rec.location.longitude
                    }
                except Exception:
                    geo[ip] = {}
            reader.close()
            out["ip_geolocation"] = geo
        except Exception:
            pass

    out["generated_at"] = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    out["log_type_detected"] = "auto"
    return out

# ----------------- helper functions -----------------
def percentile(data, p):
    if not data:
        return None
    data_sorted = sorted(data)
    k = (len(data_sorted)-1) * (p/100.0)
    f = int(k)
    c = f + 1
    if c >= len(data_sorted):
        return data_sorted[-1]
    d0 = data_sorted[f] * (c - k)
    d1 = data_sorted[c] * (k - f)
    return d0 + d1

def detect_log_formats(content, summary_out):
    """
    Improved heuristics that return human-friendly format names.
    """
    scores = defaultdict(int)
    if re.search(r'\d+\.\d+\.\d+\.\d+ - - \[', content):
        scores['apache/nginx_access'] += 4
    if re.search(r'"\w+ /.+ HTTP/\d\.\d"', content):
        scores['apache/nginx_access'] += 2
    if re.search(r'nginx', content, re.IGNORECASE):
        scores['nginx'] += 3
    if re.search(r'apache', content, re.IGNORECASE):
        scores['apache'] += 2
    if re.search(r'^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+\s+\S+', content, re.MULTILINE):
        scores['syslog'] += 3
    if re.search(r'EventID=|EventRecordID=|ProviderName=|<Event ', content, re.IGNORECASE):
        scores['windows_event'] += 3
    if re.search(r'^\s*{.*"level".*".*"}', content, re.MULTILINE) or re.search(r'"\bmessage\b".*', content):
        scores['json'] += 2
    if 'Traceback (most recent call last)' in content or re.search(r'\bat java\.', content):
        scores['application_stack'] += 2
    if summary_out.get("top_endpoints") and isinstance(summary_out["top_endpoints"], dict):
        # common indicator of web access logs
        scores['web_access_log'] += 1
    ordered = sorted(scores.items(), key=lambda x: x[1], reverse=True)
    return [k for k, v in ordered if v > 0]

def compute_risk_and_messages(errors, warnings, failed_logins, sqli_count, xss_count, bruteforce_count, total_lines):
    """
    Compute heuristic risk score (0-100) and produce human messages.
    """
    score = 10  # baseline
    messages = []

    # proportional contributions
    if errors:
        # scale errors per 1k lines up to 30 points
        score += min(30, int((errors / max(1, total_lines)) * 1000))
        messages.append(f"Detected {errors} error lines.")
    if warnings:
        score += min(15, int((warnings / max(1, total_lines)) * 500))
        messages.append(f"Detected {warnings} warnings.")
    if failed_logins:
        score += min(20, failed_logins * 2)
        messages.append(f"{failed_logins} failed login attempts found.")
    if bruteforce_count:
        score += min(25, bruteforce_count * 10)
        messages.append(f"Brute-force patterns detected ({bruteforce_count} sources).")
    if sqli_count:
        score += min(40, sqli_count * 10)
        messages.append(f"SQL injection indicators: {sqli_count} samples.")
    if xss_count:
        score += min(40, xss_count * 10)
        messages.append(f"XSS indicators: {xss_count} samples.")

    # clamp 0-100
    score = max(0, min(100, score))

    # human-friendly summary
    human_msg = []
    if score >= 75:
        human_msg.append("High risk — immediate investigation recommended.")
    elif score >= 45:
        human_msg.append("Medium risk — review alerts and investigate suspicious activity.")
    elif score > 20:
        human_msg.append("Low-medium risk — monitor and check notable warnings.")
    else:
        human_msg.append("Low risk — no major security issues detected.")

    return score, human_msg + messages

# ----------------- API & DOWNLOAD -----------------
@app.route("/api/result/<filename>")
def api_result(filename):
    report_path = os.path.join(REPORT_FOLDER, f"{filename}.json")
    if not os.path.exists(report_path):
        return jsonify({"error": "Report not found"}), 404
    with open(report_path, "r") as f:
        result = json.load(f)
    return jsonify(result)

@app.route("/download/<filename>")
def download_report(filename):
    report_path = os.path.join(REPORT_FOLDER, f"{filename}.json")
    if not os.path.exists(report_path):
        return jsonify({"error": "Report not found"}), 404
    with open(report_path, "r") as f:
        result = json.load(f)
    si = StringIO()
    cw = csv.writer(si)
    cw.writerow(["Metric", "Value"])
    for key, value in result.items():
        cw.writerow([key, json.dumps(value) if isinstance(value, (dict, list)) else value])
    si.seek(0)
    return send_file(StringIO(si.getvalue()), mimetype="text/csv", as_attachment=True, download_name=f"{filename}_report.csv")

# ----------------- RUN -----------------
if __name__ == "__main__":
    app.run(debug=True)
