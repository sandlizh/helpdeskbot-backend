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

app = Flask(__name__)
CORS(app, origins="*")

DB_PATH = "helpdeskbot.db"
MIAMI_EMAIL_REGEX = r"^[a-z][a-z0-9]{2,24}@miamioh\.edu$"
EASTERN_TZ = pytz.timezone("America/New_York")

# ===== Resend settings (HTTP API) =====
RESEND_API_KEY = os.environ.get("RESEND_API_KEY", "")
FROM_EMAIL = os.environ.get("FROM_EMAIL", "")  # e.g. "HelpDeskBot <onboarding@resend.dev>"

APP_PUBLIC_URL = os.environ.get("APP_PUBLIC_URL", "").rstrip("/")
VERIFY_SECRET = os.environ.get("VERIFY_SECRET", "")

VERIFY_TOKEN_TTL_MINUTES = 30


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
    """
    Send email via Resend HTTPS API (works on Render; no SMTP ports needed).
    """
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


def get_current_week_range():
    today = now_eastern().date()
    monday = today - timedelta(days=today.weekday())
    sunday = monday + timedelta(days=6)
    return monday, sunday


def count_events_this_week(ical_url):
    resp = requests.get(ical_url, timeout=20)
    resp.raise_for_status()

    cal = Calendar.from_ical(resp.content)
    monday, sunday = get_current_week_range()

    count = 0
    for component in cal.walk():
        if component.name == "VEVENT":
            dtstart = component.get("dtstart").dt
            if hasattr(dtstart, "date"):
                event_date = dtstart.date()
            else:
                event_date = dtstart

            if monday <= event_date <= sunday:
                count += 1

    return count


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

    # 1) Insert user as unverified
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

    # 2) Send email; if it fails, delete the user so you can retry cleanly
    try:
        send_verification_email(email, verify_link)
    except Exception as e:
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


@app.route("/api/assignments/week", methods=["POST"])
def assignments_week():
    data = request.get_json() or {}
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


if __name__ == "__main__":
    ensure_users_table_and_columns()
    app.run(debug=True)
