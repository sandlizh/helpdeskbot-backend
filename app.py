import os
import re
import sqlite3
import secrets
from datetime import datetime, timedelta

import pytz
import requests
from flask import Flask, request, jsonify, redirect
from flask_cors import CORS
from icalendar import Calendar
from werkzeug.security import generate_password_hash, check_password_hash
from dateutil import parser as dtparser

app = Flask(__name__)
CORS(app, origins="*")

DB_PATH = "helpdeskbot.db"
MIAMI_EMAIL_REGEX = r"^[a-z][a-z0-9]{2,24}@miamioh\.edu$"
EASTERN_TZ = pytz.timezone("America/New_York")

# --- Email (HTTP API via Resend) ---
# Set these in Render environment variables:
# RESEND_API_KEY   = your key
# EMAIL_FROM       = something like "HelpDeskBot <onboarding@resend.dev>" (or your verified domain sender)
# APP_PUBLIC_URL   = "https://sandlizh.github.io/helpdeskbot-frontend/"  (no trailing slash preferred)
RESEND_API_KEY = os.getenv("RESEND_API_KEY", "").strip()
EMAIL_FROM = os.getenv("EMAIL_FROM", "").strip()
APP_PUBLIC_URL = os.getenv("APP_PUBLIC_URL", "").strip().rstrip("/")

# --- Canvas ---
# For MiamiOH Canvas
CANVAS_BASE_URL = "https://miamioh.instructure.com"


# ---------------------------
# DB helpers / migrations
# ---------------------------

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def column_exists(conn, table, column):
    cur = conn.cursor()
    cur.execute(f"PRAGMA table_info({table})")
    cols = [row[1] for row in cur.fetchall()]
    return column in cols


def init_db():
    conn = get_db()
    cur = conn.cursor()

    # Base table (original fields)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            ical_url TEXT NOT NULL
        );
    """)

    # Add new columns if missing (simple migration)
    if not column_exists(conn, "users", "is_verified"):
        cur.execute("ALTER TABLE users ADD COLUMN is_verified INTEGER DEFAULT 0;")

    if not column_exists(conn, "users", "verify_token"):
        cur.execute("ALTER TABLE users ADD COLUMN verify_token TEXT;")

    if not column_exists(conn, "users", "verify_token_expires"):
        cur.execute("ALTER TABLE users ADD COLUMN verify_token_expires TEXT;")

    if not column_exists(conn, "users", "canvas_token"):
        cur.execute("ALTER TABLE users ADD COLUMN canvas_token TEXT;")

    conn.commit()
    conn.close()


init_db()


# ---------------------------
# Date helpers (Mon-Sun)
# ---------------------------

def get_week_range_datetimes():
    """
    Returns (start_dt, end_dt) in Eastern time.
    start_dt = Monday 00:00:00
    end_dt   = Sunday 23:59:59
    """
    now = datetime.now(EASTERN_TZ)
    today = now.date()
    monday = today - timedelta(days=today.weekday())
    sunday = monday + timedelta(days=6)

    start_dt = EASTERN_TZ.localize(datetime(monday.year, monday.month, monday.day, 0, 0, 0))
    end_dt = EASTERN_TZ.localize(datetime(sunday.year, sunday.month, sunday.day, 23, 59, 59))
    return start_dt, end_dt


# ---------------------------
# iCal counting (fallback)
# ---------------------------

def count_ical_events_this_week(ical_url):
    resp = requests.get(ical_url, timeout=25)
    resp.raise_for_status()

    cal = Calendar.from_ical(resp.content)
    start_dt, end_dt = get_week_range_datetimes()

    count = 0

    for component in cal.walk():
        if component.name != "VEVENT":
            continue

        dtstart = component.get("dtstart")
        if not dtstart:
            continue

        dt = dtstart.dt

        # date vs datetime handling
        if isinstance(dt, datetime):
            if dt.tzinfo is None:
                dt = pytz.utc.localize(dt)
            dt_e = dt.astimezone(EASTERN_TZ)
        else:
            # If it's a date only, treat it as midnight Eastern
            dt_e = EASTERN_TZ.localize(datetime(dt.year, dt.month, dt.day, 0, 0, 0))

        if start_dt <= dt_e <= end_dt:
            count += 1

    return count


# ---------------------------
# Canvas counting (all items + assignments subset)
# ---------------------------

def count_canvas_items_and_assignments_this_week(canvas_token):
    """
    Returns:
      {
        "calendar_items_this_week": <int>,   # all Canvas planner items in the week
        "assignments_this_week": <int>       # only assignments in the week
      }
    """
    start_dt, end_dt = get_week_range_datetimes()

    start_utc = start_dt.astimezone(pytz.utc).isoformat()
    end_utc = end_dt.astimezone(pytz.utc).isoformat()

    url = f"{CANVAS_BASE_URL}/api/v1/planner/items"
    headers = {"Authorization": f"Bearer {canvas_token}"}
    params = {"start_date": start_utc, "end_date": end_utc, "per_page": 100}

    items = []
    next_url = url

    while next_url:
        r = requests.get(
            next_url,
            headers=headers,
            params=params if next_url == url else None,
            timeout=20
        )

        if r.status_code == 401:
            raise RuntimeError("Canvas token unauthorized.")
        if r.status_code >= 400:
            raise RuntimeError(f"Canvas API error {r.status_code}: {r.text[:200]}")

        batch = r.json()
        if isinstance(batch, list):
            items.extend(batch)

        # pagination
        link = r.headers.get("Link", "")
        next_link = None
        if link:
            for part in link.split(","):
                if 'rel="next"' in part:
                    seg = part.split(";")[0].strip()
                    if seg.startswith("<") and seg.endswith(">"):
                        next_link = seg[1:-1]
        next_url = next_link

    total_items = 0
    assignment_items = 0

    for it in items:
        # planner date fields vary
        due_at = (
            it.get("plannable_date")
            or it.get("due_at")
            or it.get("planner_override", {}).get("plannable_date")
            or it.get("planner_override", {}).get("due_at")
        )
        if not due_at:
            continue

        try:
            due_dt = dtparser.isoparse(due_at)
        except Exception:
            continue

        if due_dt.tzinfo is None:
            due_dt = pytz.utc.localize(due_dt)

        due_eastern = due_dt.astimezone(EASTERN_TZ)

        if start_dt <= due_eastern <= end_dt:
            total_items += 1
            if (it.get("plannable_type") or "").lower() == "assignment":
                assignment_items += 1

    return {
        "calendar_items_this_week": total_items,
        "assignments_this_week": assignment_items
    }


# ---------------------------
# Email verification (Resend)
# ---------------------------

def send_verification_email(to_email, verify_link):
    """
    Sends email via Resend HTTP API.
    """
    if not RESEND_API_KEY or not EMAIL_FROM or not APP_PUBLIC_URL:
        raise RuntimeError("Email env vars missing (RESEND_API_KEY, EMAIL_FROM, APP_PUBLIC_URL).")

    subject = "Verify your HelpDeskBot account"
    html = f"""
      <p>Hi!</p>
      <p>Please verify your HelpDeskBot account by clicking this link:</p>
      <p><a href="{verify_link}">{verify_link}</a></p>
      <p>If you didn’t sign up, you can ignore this email.</p>
    """

    resp = requests.post(
        "https://api.resend.com/emails",
        headers={
            "Authorization": f"Bearer {RESEND_API_KEY}",
            "Content-Type": "application/json"
        },
        json={
            "from": EMAIL_FROM,
            "to": [to_email],
            "subject": subject,
            "html": html
        },
        timeout=25
    )

    if resp.status_code >= 400:
        raise RuntimeError(f"Email send failed: {resp.status_code} {resp.text[:200]}")


# ---------------------------
# Routes
# ---------------------------

@app.get("/")
def health():
    return jsonify({"status": "ok"}), 200


@app.post("/api/register")
def register():
    data = request.get_json() or {}

    email = (data.get("email") or "").strip().lower()
    password = (data.get("password") or "").strip()
    ical_url = (data.get("ical_url") or "").strip()

    if not re.match(MIAMI_EMAIL_REGEX, email):
        return jsonify({"error": "Invalid Miami email"}), 400
    if not password or not ical_url:
        return jsonify({"error": "Missing required fields"}), 400

    password_hash = generate_password_hash(password)

    verify_token = secrets.token_urlsafe(32)
    expires = datetime.now(EASTERN_TZ) + timedelta(hours=24)

    conn = get_db()
    cur = conn.cursor()

    try:
        cur.execute("""
            INSERT INTO users (email, password_hash, ical_url, is_verified, verify_token, verify_token_expires)
            VALUES (?, ?, ?, 0, ?, ?)
        """, (email, password_hash, ical_url, verify_token, expires.isoformat()))
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({"error": "Email already registered"}), 400

    conn.close()

    # Build verify URL on backend, then redirect user back to frontend login
    verify_link = f"https://helpdeskbot-backend.onrender.com/api/verify?token={verify_token}"

    try:
        send_verification_email(email, verify_link)
    except Exception as e:
        # If email fails, user is created but not verified
        return jsonify({"error": f"Account created but email failed to send: {str(e)}"}), 500

    return jsonify({"message": "Account created. Please verify your email."}), 201


@app.get("/api/verify")
def verify():
    token = (request.args.get("token") or "").strip()
    if not token:
        return jsonify({"error": "Missing token"}), 400

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id, verify_token_expires, is_verified FROM users WHERE verify_token = ?", (token,))
    row = cur.fetchone()

    if not row:
        conn.close()
        return jsonify({"error": "Invalid or already used token"}), 400

    if int(row["is_verified"] or 0) == 1:
        conn.close()
        return jsonify({"message": "Already verified"}), 200

    exp_raw = row["verify_token_expires"]
    if exp_raw:
        try:
            exp_dt = dtparser.isoparse(exp_raw)
            if exp_dt.tzinfo is None:
                exp_dt = EASTERN_TZ.localize(exp_dt)
        except Exception:
            exp_dt = None

        if exp_dt and datetime.now(EASTERN_TZ) > exp_dt:
            conn.close()
            return jsonify({"error": "Token expired"}), 400

    cur.execute("""
        UPDATE users
        SET is_verified = 1,
            verify_token = NULL,
            verify_token_expires = NULL
        WHERE id = ?
    """, (row["id"],))
    conn.commit()
    conn.close()

    # Redirect to your frontend login page
    if APP_PUBLIC_URL:
        return redirect(f"{APP_PUBLIC_URL}/index.html")
    return jsonify({"message": "Verified. You may now log in."}), 200


@app.post("/api/login")
def login():
    data = request.get_json() or {}

    email = (data.get("email") or "").strip().lower()
    password = (data.get("password") or "").strip()

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE email = ?", (email,))
    user = cur.fetchone()
    conn.close()

    if not user or not check_password_hash(user["password_hash"], password):
        return jsonify({"error": "Invalid login"}), 401

    if int(user["is_verified"] or 0) == 0:
        return jsonify({"error": "Email not verified"}), 403

    return jsonify({"message": "Login successful"}), 200


@app.post("/api/canvas/token")
def canvas_token():
    data = request.get_json() or {}
    email = (data.get("email") or "").strip().lower()
    token = (data.get("canvas_token") or "").strip()

    if not email or not token:
        return jsonify({"error": "Missing email or canvas_token"}), 400

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id FROM users WHERE email = ?", (email,))
    row = cur.fetchone()
    if not row:
        conn.close()
        return jsonify({"error": "User not found"}), 404

    cur.execute("UPDATE users SET canvas_token = ? WHERE email = ?", (token, email))
    conn.commit()
    conn.close()

    return jsonify({"message": "Canvas token saved"}), 200


@app.post("/api/assignments/week")
def assignments_week():
    data = request.get_json() or {}
    email = (data.get("email") or "").strip().lower()

    if not email:
        return jsonify({"error": "Missing email"}), 400

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT ical_url, canvas_token FROM users WHERE email = ?", (email,))
    row = cur.fetchone()
    conn.close()

    if not row:
        return jsonify({"error": "User not found"}), 404

    # Prefer Canvas if connected
    if row["canvas_token"]:
        try:
            counts = count_canvas_items_and_assignments_this_week(row["canvas_token"])
            return jsonify({
                "calendar_items_this_week": counts["calendar_items_this_week"],
                "assignments_this_week": counts["assignments_this_week"],
                "source": "canvas"
            }), 200
        except Exception as e:
            # fallback to iCal
            try:
                ical_count = count_ical_events_this_week(row["ical_url"])
                return jsonify({
                    "calendar_items_this_week": ical_count,
                    "assignments_this_week": ical_count,
                    "source": "ical_fallback",
                    "canvas_error": str(e)
                }), 200
            except Exception:
                return jsonify({"error": "Failed to read Canvas and iCal"}), 500

    # If no Canvas token, use iCal
    try:
        ical_count = count_ical_events_this_week(row["ical_url"])
        return jsonify({
            "calendar_items_this_week": ical_count,
            "assignments_this_week": ical_count,
            "source": "ical"
        }), 200
    except Exception:
        return jsonify({"error": "Failed to read calendar"}), 500


# ---------------------------
# Debug routes (optional)
# ---------------------------

@app.get("/api/debug/user")
def debug_user():
    email = (request.args.get("email") or "").strip().lower()
    if not email:
        return jsonify({"error": "Missing email"}), 400

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT email, ical_url, is_verified, canvas_token FROM users WHERE email = ?", (email,))
    row = cur.fetchone()
    conn.close()

    if not row:
        return jsonify({"error": "User not found"}), 404

    return jsonify({
        "email": row["email"],
        "ical_url": row["ical_url"],
        "is_verified": int(row["is_verified"] or 0),
        "has_canvas_token": bool(row["canvas_token"])
    }), 200


@app.post("/api/debug/delete_user")
def debug_delete_user():
    data = request.get_json() or {}
    email = (data.get("email") or "").strip().lower()

    if not email:
        return jsonify({"error": "Missing email"}), 400

    conn = get_db()
    cur = conn.cursor()
    cur.execute("DELETE FROM users WHERE email = ?", (email,))
    deleted = cur.rowcount
    conn.commit()
    conn.close()

    return jsonify({"deleted": deleted}), 200


if __name__ == "__main__":
    init_db()
    app.run(debug=True)
