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
    """Create the users table if it doesn't exist, using the schema you already have."""
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            ical_url TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
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
    """
    Create/update a user with email + password + iCal URL.
    Uses columns: email, password_hash, ical_url (to match your existing DB).
    """
    data = request.get_json(silent=True) or {}
    email = data.get("email")
    password = data.get("password")
    ical = data.get("ical_url")

    if not email or not password or not ical:
        return jsonify({"error": "email, password, and ical_url are required"}), 400

    conn = get_db()
    cur = conn.cursor()
    # REPLACE will overwrite existing row with same email
    cur.execute(
        "REPLACE INTO users (email, password_hash, ical_url) VALUES (?, ?, ?)",
        (email, password, ical)
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

    if not row or not row["ical_url"]:
        return jsonify({"error": "email not found or no iCal URL stored"}), 404

    ical_url = row["ical_url"]

    try:
        count = count_events_this_week(ical_url)
        return jsonify({"count": count})
    except Exception as e:
        # Optional: include str(e) while debugging, remove later if you want
        return jsonify({"error": "invalid or unreachable iCal URL", "details": str(e)}), 400


# ---------------- MAIN ---------------- #

# Make sure DB exists whenever the app starts (local or on Render)
init_db()

if __name__ == "__main__":
    app.run(debug=True)
