from flask import Flask, request, jsonify
import os
import mysql.connector
from datetime import datetime

app = Flask(__name__)

UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# --- MySQL Connection (Adjust credentials) ---
db_config = {
    'host': 'localhost',
    'user': 'root',
    'password': 'Divesh@123',
    'database': 'logx_db'
}

# Connect to MySQL (create db if not exists)
try:
    conn = mysql.connector.connect(host=db_config['host'], user=db_config['user'], password=db_config['password'])
    cursor = conn.cursor()
    cursor.execute("CREATE DATABASE IF NOT EXISTS logx_db")
    print("✅ Connected to MySQL and ensured database exists.")
except Exception as e:
    print("❌ MySQL Connection Failed:", e)

# Simple route to check API
@app.route('/')
def home():
    return jsonify({"message": "LogX Backend API Running!"})

# Upload route
@app.route('/upload', methods=['POST'])
def upload_logs():
    log_type = request.form.get("log_type", "custom")
    uploaded_file = request.files.get("file")
    text_data = request.form.get("text")

    if uploaded_file:
        filename = f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_{uploaded_file.filename}"
        save_path = os.path.join(UPLOAD_FOLDER, filename)
        uploaded_file.save(save_path)
        return jsonify({"message": f"File '{filename}' uploaded successfully!", "type": log_type})

    elif text_data:
        filename = f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_pasted.log"
        save_path = os.path.join(UPLOAD_FOLDER, filename)
        with open(save_path, 'w', encoding='utf-8') as f:
            f.write(text_data)
        return jsonify({"message": f"Pasted log saved as '{filename}'", "type": log_type})

    else:
        return jsonify({"message": "No file or text received!"}), 400


if __name__ == '__main__':
    app.run(debug=True)
