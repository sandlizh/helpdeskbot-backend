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
RESEND_API_KEY = os.getenv("RESEND_API_KEY", "").strip()
EMAIL_FROM = os.getenv("EMAIL_FROM", "").strip()
APP_PUBLIC_URL = os.getenv("APP_PUBLIC_URL", "").strip().rstrip("/")

# --- Canvas ---
CANVAS_BASE_URL = "https://miamioh.instructure.com"

# Canvas types we’ll treat as “assignments”
ASSIGNMENT_TYPES = {"assignment", "quiz", "discussion_topic"}


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


def get_today_in_eastern():
    return datetime.now(EASTERN_TZ).date()


def get_week_range_for(date_obj):
    monday = date_obj - timedelta(days=date_obj.weekday())
    sunday = monday + timedelta(days=6)
    return monday, sunday


def get_next_week_range():
    today = get_today_in_eastern()
    this_monday, _ = get_week_range_for(today)
    next_monday = this_monday + timedelta(days=7)
    next_sunday = next_monday + timedelta(days=6)
    return next_monday, next_sunday


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
# Canvas: fetch + summarize
# ---------------------------

def canvas_fetch_planner_items(canvas_token, start_dt_utc_iso, end_dt_utc_iso):
    url = f"{CANVAS_BASE_URL}/api/v1/planner/items"
    headers = {"Authorization": f"Bearer {canvas_token}"}
    params = {"start_date": start_dt_utc_iso, "end_date": end_dt_utc_iso, "per_page": 100}

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


def summarize_canvas_items(items, start_dt, end_dt):
    """
    Returns:
      calendar_items: all items in range
      assignments: only assignment-like types (assignment/quiz/discussion_topic)
      assignment_items: list with title/course/type/due_at/url
    """
    calendar_count = 0
    assignment_list = []

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

        calendar_count += 1

        ptype = (it.get("plannable_type") or "").lower()
        if ptype in ASSIGNMENT_TYPES:
            title = it.get("plannable", {}).get("title") or it.get("title") or "Untitled"
            course = it.get("context_name") or "Canvas"
            url = it.get("html_url") or it.get("plannable", {}).get("html_url")

            assignment_list.append({
                "title": title,
                "course": course,
                "type": ptype,
                "due_at": due_dt.astimezone(EASTERN_TZ).isoformat(),
                "url": url
            })

    assignment_list.sort(key=lambda x: x.get("due_at") or "9999-12-31T23:59:59-05:00")

    return {
        "calendar_items": calendar_count,
        "assignments": len(assignment_list),
        "assignment_items": assignment_list
    }


def count_canvas_items_and_assignments_this_week(canvas_token):
    start_dt, end_dt = get_week_range_datetimes()
    start_utc = start_dt.astimezone(pytz.utc).isoformat()
    end_utc = end_dt.astimezone(pytz.utc).isoformat()

    items = canvas_fetch_planner_items(canvas_token, start_utc, end_utc)
    summary = summarize_canvas_items(items, start_dt, end_dt)

    return {
        "calendar_items_this_week": summary["calendar_items"],
        "assignments_this_week": summary["assignments"]
    }


# ---------------------------
# Email verification (Resend)
# ---------------------------

def send_verification_email(to_email, verify_link):
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

    if row["canvas_token"]:
        try:
            counts = count_canvas_items_and_assignments_this_week(row["canvas_token"])
            return jsonify({
                "calendar_items_this_week": counts["calendar_items_this_week"],
                "assignments_this_week": counts["assignments_this_week"],
                "source": "canvas"
            }), 200
        except Exception as e:
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
# NEW: Assignments overview + list endpoints
# ---------------------------

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

    if not row or not row["canvas_token"]:
        return jsonify({"error": "Canvas token not set for user"}), 400

    token = row["canvas_token"]

    try:
        today = get_today_in_eastern()
        tomorrow = today + timedelta(days=1)

        this_monday, this_sunday = get_week_range_for(today)
        next_monday, next_sunday = get_next_week_range()

        # Build big range: today -> next week Sunday
        start_dt = EASTERN_TZ.localize(datetime(today.year, today.month, today.day, 0, 0, 0))
        end_dt = EASTERN_TZ.localize(datetime(next_sunday.year, next_sunday.month, next_sunday.day, 23, 59, 59))

        items = canvas_fetch_planner_items(
            token,
            start_dt.astimezone(pytz.utc).isoformat(),
            end_dt.astimezone(pytz.utc).isoformat()
        )

        def summarize_for_day(d):
            s = EASTERN_TZ.localize(datetime(d.year, d.month, d.day, 0, 0, 0))
            e = EASTERN_TZ.localize(datetime(d.year, d.month, d.day, 23, 59, 59))
            return summarize_canvas_items(items, s, e)

        def summarize_for_week(monday, sunday):
            s = EASTERN_TZ.localize(datetime(monday.year, monday.month, monday.day, 0, 0, 0))
            e = EASTERN_TZ.localize(datetime(sunday.year, sunday.month, sunday.day, 23, 59, 59))
            return summarize_canvas_items(items, s, e)

        today_sum = summarize_for_day(today)
        tomorrow_sum = summarize_for_day(tomorrow)
        this_week_sum = summarize_for_week(this_monday, this_sunday)
        next_week_sum = summarize_for_week(next_monday, next_sunday)

        # Next 5 upcoming assignments from today -> next week
        big_sum = summarize_canvas_items(items, start_dt, end_dt)
        upcoming = big_sum["assignment_items"][:5]

        return jsonify({
            "source": "canvas",
            "today": {
                "calendar_items": today_sum["calendar_items"],
                "assignments": today_sum["assignments"],
                "date": str(today),
            },
            "tomorrow": {
                "calendar_items": tomorrow_sum["calendar_items"],
                "assignments": tomorrow_sum["assignments"],
                "date": str(tomorrow),
            },
            "this_week": {
                "calendar_items": this_week_sum["calendar_items"],
                "assignments": this_week_sum["assignments"],
                "start": str(this_monday),
                "end": str(this_sunday),
            },
            "next_week": {
                "calendar_items": next_week_sum["calendar_items"],
                "assignments": next_week_sum["assignments"],
                "start": str(next_monday),
                "end": str(next_sunday),
            },
            "upcoming_assignments": upcoming
        }), 200

    except Exception as e:
        return jsonify({"error": f"Canvas request failed: {str(e)}"}), 500


@app.post("/api/assignments/list")
def assignments_list():
    """
    Body:
      { "email": "...", "start_date": "YYYY-MM-DD", "end_date": "YYYY-MM-DD" }
    Returns assignment-like items list and counts
    """
    data = request.get_json() or {}
    email = (data.get("email") or "").strip().lower()
    start_date = (data.get("start_date") or "").strip()
    end_date = (data.get("end_date") or "").strip()

    if not email or not start_date or not end_date:
        return jsonify({"error": "Missing email/start_date/end_date"}), 400

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT canvas_token FROM users WHERE email = ?", (email,))
    row = cur.fetchone()
    conn.close()

    if not row or not row["canvas_token"]:
        return jsonify({"error": "Canvas token not set for user"}), 400

    token = row["canvas_token"]

    try:
        # make eastern day bounds
        sd = dtparser.isoparse(start_date).date()
        ed = dtparser.isoparse(end_date).date()

        start_dt = EASTERN_TZ.localize(datetime(sd.year, sd.month, sd.day, 0, 0, 0))
        end_dt = EASTERN_TZ.localize(datetime(ed.year, ed.month, ed.day, 23, 59, 59))

        items = canvas_fetch_planner_items(
            token,
            start_dt.astimezone(pytz.utc).isoformat(),
            end_dt.astimezone(pytz.utc).isoformat()
        )

        summary = summarize_canvas_items(items, start_dt, end_dt)

        return jsonify({
            "source": "canvas",
            "calendar_items_this_range": summary["calendar_items"],
            "assignments_this_range": summary["assignments"],
            "items": summary["assignment_items"]
        }), 200

    except Exception as e:
        return jsonify({"error": f"Canvas request failed: {str(e)}"}), 500


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
