from flask import Flask, request, jsonify
from flask_cors import CORS
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import re
from datetime import datetime, timedelta
import requests
from icalendar import Calendar

app = Flask(__name__)
CORS(app, origins="*")

DB_PATH = "helpdeskbot.db"

MIAMI_EMAIL_REGEX = r"^[a-z][a-z0-9]{2,24}@miamioh\.edu$"


# ---------------- DATABASE ---------------- #

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            ical_url TEXT NOT NULL
        );
    """)
    conn.commit()
    conn.close()


# ---------------- ICAL LOGIC ---------------- #

def count_events_this_week(ical_url):
    resp = requests.get(ical_url)
    resp.raise_for_status()

    cal = Calendar.from_ical(resp.content)

    today = datetime.now().date()
    monday = today - timedelta(days=today.weekday())
    sunday = monday + timedelta(days=6)

    count = 0
    for component in cal.walk():
        if component.name == "VEVENT":
            dtstart = component.get("dtstart").dt
            event_date = dtstart.date() if hasattr(dtstart, "date") else dtstart
            if monday <= event_date <= sunday:
                count += 1

    return count


# ---------------- API ROUTES ---------------- #

@app.route("/api/register", methods=["POST"])
def register():
    data = request.get_json()
    email = data.get("email", "").strip().lower()
    password = data.get("password", "")
    ical_url = data.get("ical_url", "").strip()

    if not re.match(MIAMI_EMAIL_REGEX, email):
        return jsonify({"error": "Invalid Miami email"}), 400

    if not password or not ical_url:
        return jsonify({"error": "Missing required fields"}), 400

    password_hash = generate_password_hash(password)

    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute(
            "INSERT INTO users (email, password_hash, ical_url) VALUES (?, ?, ?)",
            (email, password_hash, ical_url)
        )
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({"error": "Email already registered"}), 400

    conn.close()
    return jsonify({"message": "Account created"}), 201


@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json()
    email = data.get("email", "").strip().lower()
    password = data.get("password", "")

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE email = ?", (email,))
    user = cur.fetchone()
    conn.close()

    if not user or not check_password_hash(user["password_hash"], password):
        return jsonify({"error": "Invalid login"}), 401

    return jsonify({"message": "Login successful"}), 200


@app.route("/api/assignments/week", methods=["POST"])
def assignments_week():
    data = request.get_json()
    email = data.get("email", "").strip().lower()

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT ical_url FROM users WHERE email = ?", (email,))
    row = cur.fetchone()
    conn.close()

    if not row:
        return jsonify({"error": "User not found"}), 404

    try:
        count = count_events_this_week(row["ical_url"])
        return jsonify({"assignments_this_week": count}), 200
    except Exception:
        return jsonify({"error": "Failed to read calendar"}), 500


# ---------------- STARTUP ---------------- #

if __name__ == "__main__":
    init_db()
    app.run(debug=True)
