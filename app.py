import os
import re
import sqlite3
import secrets
from datetime import datetime, timedelta

import pytz
import requests
from flask import Flask, request, jsonify, redirect
from flask_cors import CORS
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
# EMAIL_FROM       = e.g. "HelpDeskBot <onboarding@resend.dev>" (or your verified sender)
# APP_PUBLIC_URL   = "https://sandlizh.github.io/helpdeskbot-frontend"  (no trailing slash)
RESEND_API_KEY = os.getenv("RESEND_API_KEY", "").strip()
EMAIL_FROM = os.getenv("EMAIL_FROM", "").strip()
APP_PUBLIC_URL = os.getenv("APP_PUBLIC_URL", "").strip().rstrip("/")

# --- Canvas ---
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

    # NOTE: Keep ical_url column for compatibility, but we won't use it anymore.
    # Make it nullable in the CREATE (existing DBs may still have NOT NULL).
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            ical_url TEXT,
            is_verified INTEGER DEFAULT 0,
            verify_token TEXT,
            verify_token_expires TEXT,
            canvas_token TEXT
        );
    """)

    # Simple migrations for older DBs (adds missing columns if needed)
    if not column_exists(conn, "users", "is_verified"):
        cur.execute("ALTER TABLE users ADD COLUMN is_verified INTEGER DEFAULT 0;")

    if not column_exists(conn, "users", "verify_token"):
        cur.execute("ALTER TABLE users ADD COLUMN verify_token TEXT;")

    if not column_exists(conn, "users", "verify_token_expires"):
        cur.execute("ALTER TABLE users ADD COLUMN verify_token_expires TEXT;")

    if not column_exists(conn, "users", "canvas_token"):
        cur.execute("ALTER TABLE users ADD COLUMN canvas_token TEXT;")

    # If the original table didn't have ical_url, add it
    if not column_exists(conn, "users", "ical_url"):
        cur.execute("ALTER TABLE users ADD COLUMN ical_url TEXT;")

    conn.commit()
    conn.close()


init_db()


# ---------------------------
# Date helpers (Eastern)
# ---------------------------

def _localize_eastern(y, m, d, hh=0, mm=0, ss=0):
    return EASTERN_TZ.localize(datetime(y, m, d, hh, mm, ss))


def get_today_range():
    now = datetime.now(EASTERN_TZ)
    d = now.date()
    start_dt = _localize_eastern(d.year, d.month, d.day, 0, 0, 0)
    end_dt = _localize_eastern(d.year, d.month, d.day, 23, 59, 59)
    return start_dt, end_dt


def get_tomorrow_range():
    now = datetime.now(EASTERN_TZ)
    d = (now + timedelta(days=1)).date()
    start_dt = _localize_eastern(d.year, d.month, d.day, 0, 0, 0)
    end_dt = _localize_eastern(d.year, d.month, d.day, 23, 59, 59)
    return start_dt, end_dt


def get_this_week_range():
    """
    Monday 00:00:00 -> Sunday 23:59:59 (Eastern)
    """
    now = datetime.now(EASTERN_TZ)
    today = now.date()
    monday = today - timedelta(days=today.weekday())
    sunday = monday + timedelta(days=6)

    start_dt = _localize_eastern(monday.year, monday.month, monday.day, 0, 0, 0)
    end_dt = _localize_eastern(sunday.year, sunday.month, sunday.day, 23, 59, 59)
    return start_dt, end_dt


def get_next_week_range():
    """
    Next Monday 00:00:00 -> Next Sunday 23:59:59 (Eastern)
    """
    this_start, _ = get_this_week_range()
    next_monday = (this_start + timedelta(days=7)).date()
    next_sunday = next_monday + timedelta(days=6)

    start_dt = _localize_eastern(next_monday.year, next_monday.month, next_monday.day, 0, 0, 0)
    end_dt = _localize_eastern(next_sunday.year, next_sunday.month, next_sunday.day, 23, 59, 59)
    return start_dt, end_dt


# ---------------------------
# Canvas helpers
# ---------------------------

def _canvas_fetch_planner_items(canvas_token, start_dt_eastern, end_dt_eastern):
    """
    Fetches Canvas planner items for a date range (returns list of items).
    """
    start_utc = start_dt_eastern.astimezone(pytz.utc).isoformat()
    end_utc = end_dt_eastern.astimezone(pytz.utc).isoformat()

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

    return items


def count_canvas_items_and_assignments(canvas_token, start_dt, end_dt):
    """
    Counts:
      - all planner items in range
      - assignment planner items in range
    """
    items = _canvas_fetch_planner_items(canvas_token, start_dt, end_dt)

    total_items = 0
    assignment_items = 0

    for it in items:
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
        "calendar_items": total_items,
        "assignments": assignment_items
    }


def list_canvas_items_in_range(canvas_token, start_dt, end_dt):
    """
    Returns a normalized list of items in the range + counts.
    Each item includes title/type/due date (local)/url when available.
    """
    items = _canvas_fetch_planner_items(canvas_token, start_dt, end_dt)

    normalized = []
    total_items = 0
    assignment_items = 0

    for it in items:
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

        if not (start_dt <= due_eastern <= end_dt):
            continue

        total_items += 1

        ptype = (it.get("plannable_type") or "").lower()
        is_assignment = (ptype == "assignment")
        if is_assignment:
            assignment_items += 1

        title = (
            it.get("plannable", {}).get("title")
            or it.get("plannable", {}).get("name")
            or it.get("title")
            or it.get("context_name")
            or "Untitled"
        )

        # Try to capture a link (Canvas often provides html_url, but not always)
        html_url = (
            it.get("html_url")
            or it.get("plannable", {}).get("html_url")
            or it.get("plannable", {}).get("url")
            or ""
        )

        normalized.append({
            "title": title,
            "type": ptype or "item",
            "due_at": due_dt.isoformat(),
            "due_at_local": due_eastern.strftime("%Y-%m-%d %I:%M %p ET"),
            "url": html_url
        })

    # Sort by due date
    normalized.sort(key=lambda x: x.get("due_at", ""))

    return {
        "calendar_items": total_items,
        "assignments": assignment_items,
        "items": normalized
    }


# ---------------------------
# Email verification (Resend)
# ---------------------------

def send_verification_email(to_email, verify_link):
    """
    Sends email via Resend HTTP API.
    NOTE: We intentionally DO NOT use <a href="..."> to avoid link tracking rewriting
    verification links (which can break verification).
    """
    if not RESEND_API_KEY or not EMAIL_FROM or not APP_PUBLIC_URL:
        raise RuntimeError("Email env vars missing (RESEND_API_KEY, EMAIL_FROM, APP_PUBLIC_URL).")

    subject = "Verify your HelpDeskBot account"

    # Plain-text style link (no anchor tag)
    html = f"""
      <p>Hi!</p>
      <p>Please verify your HelpDeskBot account by copying and pasting this link into your browser:</p>
      <p><code style="word-break: break-all;">{verify_link}</code></p>
      <p>If you didn’t sign up, you can ignore this email.</p>
    """

    text = (
        "Hi!\n\n"
        "Please verify your HelpDeskBot account by copying and pasting this link into your browser:\n\n"
        f"{verify_link}\n\n"
        "If you didn’t sign up, you can ignore this email.\n"
    )

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
            "html": html,
            "text": text
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


# ✅ Canvas-first registration: requires canvas_token, no iCal required
@app.post("/api/register")
def register():
    data = request.get_json() or {}

    email = (data.get("email") or "").strip().lower()
    password = (data.get("password") or "").strip()
    canvas_token = (data.get("canvas_token") or "").strip()

    if not re.match(MIAMI_EMAIL_REGEX, email):
        return jsonify({"error": "Invalid Miami email"}), 400
    if not password or not canvas_token:
        return jsonify({"error": "Missing required fields"}), 400

    password_hash = generate_password_hash(password)

    verify_token = secrets.token_urlsafe(32)
    expires = datetime.now(EASTERN_TZ) + timedelta(hours=24)

    conn = get_db()
    cur = conn.cursor()

    try:
        # ical_url saved as placeholder for compatibility
        cur.execute("""
            INSERT INTO users (email, password_hash, ical_url, canvas_token, is_verified, verify_token, verify_token_expires)
            VALUES (?, ?, ?, ?, 0, ?, ?)
        """, (email, password_hash, "N/A", canvas_token, verify_token, expires.isoformat()))
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({"error": "Email already registered"}), 400

    conn.close()

    verify_link = f"https://helpdeskbot-backend.onrender.com/api/verify?token={verify_token}"

    try:
        send_verification_email(email, verify_link)
    except Exception as e:
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


# Optional: allow user to update canvas token later
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


# ✅ Canvas-only: weekly counts
@app.post("/api/assignments/week")
def assignments_week():
    data = request.get_json() or {}
    email = (data.get("email") or "").strip().lower()

    if not email:
        return jsonify({"error": "Missing email"}), 400

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT canvas_token FROM users WHERE email = ?", (email,))
    row = cur.fetchone()
    conn.close()

    if not row:
        return jsonify({"error": "User not found"}), 404

    if not row["canvas_token"]:
        return jsonify({"error": "Canvas not connected"}), 400

    start_dt, end_dt = get_this_week_range()
    counts = count_canvas_items_and_assignments(row["canvas_token"], start_dt, end_dt)

    return jsonify({
        "calendar_items_this_week": counts["calendar_items"],
        "assignments_this_week": counts["assignments"],
        "source": "canvas"
    }), 200


# ✅ Canvas-only: today / tomorrow / this week / next week counts
@app.post("/api/assignments/overview")
def assignments_overview():
    data = request.get_json() or {}
    email = (data.get("email") or "").strip().lower()

    if not email:
        return jsonify({"error": "Missing email"}), 400

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT canvas_token FROM users WHERE email = ?", (email,))
    row = cur.fetchone()
    conn.close()

    if not row:
        return jsonify({"error": "User not found"}), 404

    if not row["canvas_token"]:
        return jsonify({"error": "Canvas not connected"}), 400

    token = row["canvas_token"]

    t0, t1 = get_today_range()
    tm0, tm1 = get_tomorrow_range()
    w0, w1 = get_this_week_range()
    nw0, nw1 = get_next_week_range()

    today_counts = count_canvas_items_and_assignments(token, t0, t1)
    tomorrow_counts = count_canvas_items_and_assignments(token, tm0, tm1)
    this_week_counts = count_canvas_items_and_assignments(token, w0, w1)
    next_week_counts = count_canvas_items_and_assignments(token, nw0, nw1)

    return jsonify({
        "today": {
            "calendar_items": today_counts["calendar_items"],
            "assignments": today_counts["assignments"]
        },
        "tomorrow": {
            "calendar_items": tomorrow_counts["calendar_items"],
            "assignments": tomorrow_counts["assignments"]
        },
        "this_week": {
            "calendar_items": this_week_counts["calendar_items"],
            "assignments": this_week_counts["assignments"]
        },
        "next_week": {
            "calendar_items": next_week_counts["calendar_items"],
            "assignments": next_week_counts["assignments"]
        },
        "source": "canvas"
    }), 200


# ✅ NEW: list items by scope (today/tomorrow/this_week/next_week)
@app.post("/api/assignments/list_by_scope")
def assignments_list_by_scope():
    data = request.get_json() or {}
    email = (data.get("email") or "").strip().lower()
    scope = (data.get("scope") or "this_week").strip().lower()

    if not email:
        return jsonify({"error": "Missing email"}), 400

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT canvas_token FROM users WHERE email = ?", (email,))
    row = cur.fetchone()
    conn.close()

    if not row:
        return jsonify({"error": "User not found"}), 404

    if not row["canvas_token"]:
        return jsonify({"error": "Canvas not connected"}), 400

    # Choose range based on scope
    if scope == "today":
        start_dt, end_dt = get_today_range()
    elif scope == "tomorrow":
        start_dt, end_dt = get_tomorrow_range()
    elif scope == "next_week":
        start_dt, end_dt = get_next_week_range()
    else:
        scope = "this_week"
        start_dt, end_dt = get_this_week_range()

    try:
        result = list_canvas_items_in_range(row["canvas_token"], start_dt, end_dt)

        return jsonify({
            "scope": scope,
            "start": start_dt.date().isoformat(),
            "end": end_dt.date().isoformat(),
            "calendar_items": result["calendar_items"],
            "assignments": result["assignments"],
            "items": result["items"],
            "source": "canvas"
        }), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


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
    cur.execute("SELECT email, is_verified, canvas_token FROM users WHERE email = ?", (email,))
    row = cur.fetchone()
    conn.close()

    if not row:
        return jsonify({"error": "User not found"}), 404

    return jsonify({
        "email": row["email"],
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
