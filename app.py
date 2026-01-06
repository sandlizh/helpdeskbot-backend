from flask import Flask, request, jsonify
from flask_cors import CORS
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import re
from datetime import datetime, timedelta
import requests
from icalendar import Calendar
import pytz
import os
import secrets
import hashlib
from dateutil import parser as dtparser  # NEW

app = Flask(__name__)
CORS(app, origins="*")

DB_PATH = "helpdeskbot.db"
MIAMI_EMAIL_REGEX = r"^[a-z][a-z0-9]{2,24}@miamioh\.edu$"
EASTERN_TZ = pytz.timezone("America/New_York")

# ===== Resend settings (HTTP email) =====
RESEND_API_KEY = os.environ.get("RESEND_API_KEY", "")
FROM_EMAIL = os.environ.get("FROM_EMAIL", "")  # e.g. "HelpDeskBot <onboarding@resend.dev>"
APP_PUBLIC_URL = os.environ.get("APP_PUBLIC_URL", "").rstrip("/")
VERIFY_SECRET = os.environ.get("VERIFY_SECRET", "")
VERIFY_TOKEN_TTL_MINUTES = 30

# ===== Canvas settings =====
CANVAS_BASE_URL = os.environ.get("CANVAS_BASE_URL", "https://miamioh.instructure.com").rstrip("/")


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def ensure_users_table_and_columns():
    conn = get_db()
    cur = conn.cursor()

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            ical_url TEXT NOT NULL
        );
        """
    )

    cur.execute("PRAGMA table_info(users);")
    cols = {row["name"] for row in cur.fetchall()}

    if "is_verified" not in cols:
        cur.execute("ALTER TABLE users ADD COLUMN is_verified INTEGER NOT NULL DEFAULT 0;")
    if "verify_token_hash" not in cols:
        cur.execute("ALTER TABLE users ADD COLUMN verify_token_hash TEXT;")
    if "verify_expires_at" not in cols:
        cur.execute("ALTER TABLE users ADD COLUMN verify_expires_at TEXT;")

    # NEW: Canvas token storage
    if "canvas_token" not in cols:
        cur.execute("ALTER TABLE users ADD COLUMN canvas_token TEXT;")

    conn.commit()
    conn.close()


ensure_users_table_and_columns()


def now_eastern():
    return datetime.now(EASTERN_TZ)


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def make_verify_token() -> str:
    return secrets.token_urlsafe(32)


def token_hash(token: str) -> str:
    if not VERIFY_SECRET:
        return sha256_hex(token)
    return sha256_hex(VERIFY_SECRET + token)


def send_verification_email(to_email: str, verify_link: str):
    if not RESEND_API_KEY:
        raise RuntimeError("Missing RESEND_API_KEY env var")
    if not FROM_EMAIL:
        raise RuntimeError("Missing FROM_EMAIL env var")
    if not APP_PUBLIC_URL:
        raise RuntimeError("Missing APP_PUBLIC_URL env var")

    subject = "Verify your HelpDeskBot account"
    text_body = (
        "Welcome to HelpDeskBot!\n\n"
        "Please verify your email by clicking this link:\n"
        f"{verify_link}\n\n"
        f"This link expires in {VERIFY_TOKEN_TTL_MINUTES} minutes.\n"
        "If you did not create this account, you can ignore this email."
    )

    resp = requests.post(
        "https://api.resend.com/emails",
        headers={
            "Authorization": f"Bearer {RESEND_API_KEY}",
            "Content-Type": "application/json",
        },
        json={
            "from": FROM_EMAIL,
            "to": [to_email],
            "subject": subject,
            "text": text_body,
        },
        timeout=20,
    )

    if resp.status_code >= 400:
        raise RuntimeError(f"Resend error {resp.status_code}: {resp.text}")


def get_week_range_datetimes():
    """
    Returns (start_dt, end_dt) in Eastern timezone, covering Monday 00:00:00 through Sunday 23:59:59
    """
    today = now_eastern().date()
    monday = today - timedelta(days=today.weekday())
    start_dt = EASTERN_TZ.localize(datetime(monday.year, monday.month, monday.day, 0, 0, 0))
    end_dt = start_dt + timedelta(days=6, hours=23, minutes=59, seconds=59)
    return start_dt, end_dt


# ---------- iCal fallback ----------
def count_ical_events_this_week(ical_url: str) -> int:
    resp = requests.get(ical_url, timeout=20)
    resp.raise_for_status()

    cal = Calendar.from_ical(resp.content)
    start_dt, end_dt = get_week_range_datetimes()

    count = 0
    for component in cal.walk():
        if component.name != "VEVENT":
            continue

        dtstart = component.get("dtstart").dt

        # Convert to date or datetime safely
        if hasattr(dtstart, "date") and not isinstance(dtstart, datetime):
            # all-day date
            event_date = dtstart
            # count if within date range
            if start_dt.date() <= event_date <= end_dt.date():
                count += 1
            continue

        if isinstance(dtstart, datetime):
            # if naive, assume Eastern
            if dtstart.tzinfo is None:
                dtstart = EASTERN_TZ.localize(dtstart)
            else:
                dtstart = dtstart.astimezone(EASTERN_TZ)

            if start_dt <= dtstart <= end_dt:
                count += 1

    return count


# ---------- Canvas API ----------
def count_canvas_assignments_this_week(canvas_token: str) -> int:
    start_dt, end_dt = get_week_range_datetimes()

    # Canvas wants ISO8601 dates. We'll use UTC to be safe.
    start_utc = start_dt.astimezone(pytz.utc).isoformat()
    end_utc = end_dt.astimezone(pytz.utc).isoformat()

    url = f"{CANVAS_BASE_URL}/api/v1/planner/items"
    headers = {"Authorization": f"Bearer {canvas_token}"}

    params = {
        "start_date": start_utc,
        "end_date": end_utc,
        "per_page": 100
    }

    items = []
    next_url = url

    # Handle pagination (Canvas uses Link headers)
    while next_url:
        r = requests.get(next_url, headers=headers, params=params if next_url == url else None, timeout=20)
        if r.status_code == 401:
            raise RuntimeError("Canvas token unauthorized (401).")
        if r.status_code >= 400:
            raise RuntimeError(f"Canvas API error {r.status_code}: {r.text[:200]}")

        batch = r.json()
        if isinstance(batch, list):
            items.extend(batch)

        # Parse Link header for rel="next"
        link = r.headers.get("Link", "")
        next_link = None
        if link:
            parts = link.split(",")
            for p in parts:
                if 'rel="next"' in p:
                    seg = p.split(";")[0].strip()
                    if seg.startswith("<") and seg.endswith(">"):
                        next_link = seg[1:-1]
        next_url = next_link

    # Count assignment-like items due in range
    count = 0
    for it in items:
        # Many planner items have plannable_type like "assignment"
        ptype = (it.get("plannable_type") or "").lower()
        if ptype != "assignment":
            continue

        due_at = it.get("plannable_date") or it.get("due_at") or it.get("planner_override", {}).get("plannable_date")
        if not due_at:
            # If Canvas doesn't provide due date, skip
            continue

        try:
            due_dt = dtparser.isoparse(due_at)
        except Exception:
            continue

        if due_dt.tzinfo is None:
            due_dt = pytz.utc.localize(due_dt)

        due_eastern = due_dt.astimezone(EASTERN_TZ)
        if start_dt <= due_eastern <= end_dt:
            count += 1

    return count


# =================== ROUTES ===================

@app.route("/api/register", methods=["POST"])
def register():
    data = request.get_json() or {}

    email = data.get("email", "").strip().lower()
    password = data.get("password", "")
    ical_url = data.get("ical_url", "").strip()

    if not re.match(MIAMI_EMAIL_REGEX, email):
        return jsonify({"error": "Invalid Miami email"}), 400

    if not password or not ical_url:
        return jsonify({"error": "Missing required fields"}), 400

    password_hash = generate_password_hash(password)

    raw_token = make_verify_token()
    vhash = token_hash(raw_token)
    expires_at = (now_eastern() + timedelta(minutes=VERIFY_TOKEN_TTL_MINUTES)).isoformat()

    conn = get_db()
    cur = conn.cursor()

    try:
        cur.execute(
            """
            INSERT INTO users (email, password_hash, ical_url, is_verified, verify_token_hash, verify_expires_at)
            VALUES (?, ?, ?, 0, ?, ?)
            """,
            (email, password_hash, ical_url, vhash, expires_at),
        )
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({"error": "Email already registered"}), 400

    verify_link = f"{APP_PUBLIC_URL}/verify.html?token={raw_token}"

    try:
        send_verification_email(email, verify_link)
    except Exception as e:
        # Roll back so user can retry
        cur.execute("DELETE FROM users WHERE email = ?", (email,))
        conn.commit()
        conn.close()
        return jsonify({"error": f"Registration failed (email not sent): {str(e)}"}), 500

    conn.close()
    return jsonify({"message": "Account created. Check your email to verify your account."}), 201


@app.route("/api/verify", methods=["GET"])
def verify():
    token = request.args.get("token", "").strip()
    if not token:
        return jsonify({"error": "Missing token"}), 400

    vhash = token_hash(token)

    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "SELECT id, is_verified, verify_expires_at FROM users WHERE verify_token_hash = ?",
        (vhash,),
    )
    user = cur.fetchone()

    if not user:
        conn.close()
        return jsonify({"error": "Invalid or already used token"}), 400

    if user["is_verified"] == 1:
        conn.close()
        return jsonify({"message": "Already verified"}), 200

    expires_at = user["verify_expires_at"]
    if not expires_at:
        conn.close()
        return jsonify({"error": "Verification token missing"}), 400

    exp_dt = datetime.fromisoformat(expires_at)
    if now_eastern() > exp_dt:
        conn.close()
        return jsonify({"error": "Verification link expired. Please re-register."}), 400

    cur.execute(
        """
        UPDATE users
        SET is_verified = 1,
            verify_token_hash = NULL,
            verify_expires_at = NULL
        WHERE id = ?
        """,
        (user["id"],),
    )
    conn.commit()
    conn.close()

    return jsonify({"message": "Email verified. You can now log in."}), 200


@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json() or {}

    email = data.get("email", "").strip().lower()
    password = data.get("password", "")

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE email = ?", (email,))
    user = cur.fetchone()
    conn.close()

    if not user or not check_password_hash(user["password_hash"], password):
        return jsonify({"error": "Invalid login"}), 401

    if user["is_verified"] == 0:
        return jsonify({"error": "Email not verified. Check your inbox for the verification link."}), 403

    return jsonify({"message": "Login successful"}), 200


@app.route("/api/canvas/token", methods=["POST"])
def save_canvas_token():
    """
    Save Canvas token for a user (requires email + password).
    Body: { "email": "...", "password": "...", "canvas_token": "..." }
    """
    data = request.get_json() or {}
    email = data.get("email", "").strip().lower()
    password = data.get("password", "")
    canvas_token = (data.get("canvas_token") or "").strip()

    if not email or not password or not canvas_token:
        return jsonify({"error": "Missing required fields"}), 400

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE email = ?", (email,))
    user = cur.fetchone()

    if not user or not check_password_hash(user["password_hash"], password):
        conn.close()
        return jsonify({"error": "Invalid login"}), 401

    if user["is_verified"] == 0:
        conn.close()
        return jsonify({"error": "Email not verified"}), 403

    # Quick token sanity check (optional): call Canvas "self"
    try:
        r = requests.get(
            f"{CANVAS_BASE_URL}/api/v1/users/self",
            headers={"Authorization": f"Bearer {canvas_token}"},
            timeout=20,
        )
        if r.status_code == 401:
            conn.close()
            return jsonify({"error": "Canvas token invalid (401)"}), 400
        if r.status_code >= 400:
            conn.close()
            return jsonify({"error": f"Canvas check failed ({r.status_code})"}), 400
    except Exception:
        conn.close()
        return jsonify({"error": "Canvas token check failed"}), 400

    cur.execute("UPDATE users SET canvas_token = ? WHERE email = ?", (canvas_token, email))
    conn.commit()
    conn.close()

    return jsonify({"message": "Canvas connected successfully"}), 200


@app.route("/api/assignments/week", methods=["POST"])
def assignments_week():
    data = request.get_json() or {}
    email = data.get("email", "").strip().lower()

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
            count = count_canvas_assignments_this_week(row["canvas_token"])
            return jsonify({"assignments_this_week": count, "source": "canvas"}), 200
        except Exception as e:
            # Fall back to iCal if Canvas fails (keeps demo reliable)
            try:
                count = count_ical_events_this_week(row["ical_url"])
                return jsonify({"assignments_this_week": count, "source": "ical_fallback", "canvas_error": str(e)}), 200
            except Exception:
                return jsonify({"error": "Failed to read Canvas and calendar"}), 500

    # Otherwise use iCal
    try:
        count = count_ical_events_this_week(row["ical_url"])
        return jsonify({"assignments_this_week": count, "source": "ical"}), 200
    except Exception:
        return jsonify({"error": "Failed to read calendar"}), 500


@app.route("/api/debug/delete_user", methods=["POST"])
def debug_delete_user():
    data = request.get_json() or {}
    email = data.get("email", "").strip().lower()

    if not email:
        return jsonify({"error": "Missing email"}), 400

    conn = get_db()
    cur = conn.cursor()
    cur.execute("DELETE FROM users WHERE email = ?", (email,))
    deleted = cur.rowcount
    conn.commit()
    conn.close()

    return jsonify({"deleted": deleted}), 200


@app.route("/api/debug/clear_canvas", methods=["POST"])
def debug_clear_canvas():
    data = request.get_json() or {}
    email = data.get("email", "").strip().lower()
    if not email:
        return jsonify({"error": "Missing email"}), 400

    conn = get_db()
    cur = conn.cursor()
    cur.execute("UPDATE users SET canvas_token = NULL WHERE email = ?", (email,))
    conn.commit()
    conn.close()

    return jsonify({"message": "Canvas token cleared"}), 200


if __name__ == "__main__":
    ensure_users_table_and_columns()
    app.run(debug=True)
