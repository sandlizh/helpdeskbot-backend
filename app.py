from flask import Flask, request, jsonify
import sqlite3
from datetime import datetime, timedelta
import requests
from icalendar import Calendar

app = Flask(__name__)
DB_PATH = "helpdeskbot.db"


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
            email TEXT PRIMARY KEY,
            password TEXT,
            ical_url TEXT
        )
    """)
    conn.commit()
    conn.close()


# ---------------- ICAL LOGIC ---------------- #

def count_events_this_week(ical_url):
    """Return number of calendar events for Monday–Sunday of this week."""
    resp = requests.get(ical_url)
    resp.raise_for_status()
    cal = Calendar.from_ical(resp.content)

    today = datetime.now().date()
    monday = today - timedelta(days=today.weekday())  # Monday
    sunday = monday + timedelta(days=6)               # Sunday

    count = 0
    for component in cal.walk():
        if component.name == "VEVENT":
            dtstart = component.get("dtstart").dt
            date = dtstart.date() if hasattr(dtstart, "date") else dtstart
            if monday <= date <= sunday:
                count += 1
    return count


# ---------------- API ENDPOINTS ---------------- #

@app.route("/api/register", methods=["POST"])
def register():
    """Create/update a user with email + password + iCal URL."""
    data = request.json or {}
    email = data.get("email")
    pwd = data.get("password")
    ical = data.get("ical_url")

    if not email or not pwd or not ical:
        return jsonify({"error": "email, password, and ical_url are required"}), 400

    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "REPLACE INTO users (email, password, ical_url) VALUES (?, ?, ?)",
        (email, pwd, ical)
    )
    conn.commit()
    conn.close()

    return jsonify({"status": "ok"})


@app.route("/api/assignments/week", methods=["GET"])
def assignments_week():
    """Return the count of events for this week for the given email."""
    email = request.args.get("email")
    if not email:
        return jsonify({"error": "email query parameter is required"}), 400

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT ical_url FROM users WHERE email = ?", (email,))
    row = cur.fetchone()
    conn.close()

    if not row:
        return jsonify({"error": "email not found"}), 404

    ical_url = row["ical_url"]

    try:
        count = count_events_this_week(ical_url)
        return jsonify({"count": count})
    except Exception:
        return jsonify({"error": "invalid or unreachable iCal URL"}), 400


# ---------------- MAIN ---------------- #

# Make sure DB exists whenever the app starts (local or on Render)
init_db()

if __name__ == "__main__":
    app.run(debug=True)
