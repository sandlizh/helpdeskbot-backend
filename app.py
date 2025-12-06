from flask import Flask, request, redirect, url_for, session, jsonify
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import re
import sys
from datetime import datetime, timedelta
import requests
from icalendar import Calendar

app = Flask(__name__)
app.secret_key = "super-secret-change-me"   # change in real project

DB_PATH = "helpdeskbot.db"

# Miami email: letter + 2–24 letters/numbers, ending in @miamioh.edu
MIAMI_EMAIL_REGEX = r"^[a-z][a-z0-9]{2,24}@miamioh\.edu$"


# ---------------- DATABASE HELPERS ---------------- #

def get_db():
    """Open a connection to the SQLite database."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Create the users table if it doesn't exist."""
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        '''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            ical_url TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
        '''
    )
    conn.commit()
    conn.close()
    print("Database initialized.")


# ---------------- ICAL HELPER ---------------- #

def count_events_this_week(ical_url):
    """
    Count events in the *calendar week* of today:
    Monday through Sunday of the current week.
    """
    resp = requests.get(ical_url)
    resp.raise_for_status()

    cal = Calendar.from_ical(resp.content)

    today = datetime.now().date()

    # Monday of this week (weekday(): Monday = 0, Sunday = 6)
    monday = today - timedelta(days=today.weekday())
    # Sunday of this week
    sunday = monday + timedelta(days=6)

    count = 0
    for component in cal.walk():
        if component.name == "VEVENT":
            dtstart = component.get("dtstart").dt

            # dtstart may be datetime or date
            if hasattr(dtstart, "date"):
                event_date = dtstart.date()
            else:
                event_date = dtstart

            # Only count events between Monday and Sunday (inclusive)
            if monday <= event_date <= sunday:
                count += 1

    return count


# ---------------- ROUTES ---------------- #

@app.route("/")
def home():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return '''
    <html>
    <head>
      <title>HelpDeskBot Login</title>
      <style>
        body { font-family: Arial; background:#fff; }
        .container { max-width:400px; margin:60px auto; padding:20px;
                     border:1px solid #ccc; border-radius:8px; }
        a { color:#0066cc; }
      </style>
    </head>
    <body>
      <div class="container">
        <h2>HelpDeskBot</h2>
        <p><a href="/register">Create an account</a></p>
        <p><a href="/login">Login</a></p>
      </div>
    </body>
    </html>
    '''


@app.route("/register", methods=["GET", "POST"])
def register():
    error = ""

    if request.method == "POST":
        email = request.form["email"].strip().lower()
        password = request.form["password"]
        ical_url = request.form["ical_url"].strip()

        # Validate email
        if not re.match(MIAMI_EMAIL_REGEX, email):
            error = "Invalid Miami University email. Must be a valid UniqueID ending in @miamioh.edu."
        elif not password:
            error = "Password is required."
        else:
            password_hash = generate_password_hash(password)
            conn = get_db()
            cur = conn.cursor()
            try:
                cur.execute(
                    "INSERT INTO users (email, password_hash, ical_url) VALUES (?, ?, ?)",
                    (email, password_hash, ical_url),
                )
                conn.commit()
                conn.close()
                return redirect(url_for("login"))
            except sqlite3.IntegrityError:
                conn.close()
                error = "That email is already registered."

    error_html = f"<p class='error'>{error}</p>" if error else ""
    return f'''
    <html>
    <head>
      <title>Register</title>
      <style>
        body {{font-family:Arial; background:#fff;}}
        .container {{max-width:400px; margin:60px auto; padding:20px;
                     border:1px solid #ccc; border-radius:8px;}}
        .error {{color:red;}}
        input {{width:100%; padding:8px; margin-bottom:12px;}}
        button {{padding:8px 16px; background:#990000; color:#fff; border:none;
                 border-radius:4px; cursor:pointer;}}
        button:hover {{opacity:0.9;}}
        a {{color:#0066cc;}}
      </style>
    </head>
    <body>
      <div class="container">
        <h2>Create Account</h2>
        {error_html}
        <form method="post">
          <label>Miami Email:</label><br>
          <input type="email" name="email" placeholder="yourid@miamioh.edu" required>
          <label>Password:</label><br>
          <input type="password" name="password" placeholder="Password" required>
          <label>iCal URL (assignments calendar):</label><br>
          <input type="url" name="ical_url" placeholder="https://calendar.ics" required>
          <button type="submit">Register</button>
        </form>
        <p><a href="/login">Already have an account? Login</a></p>
      </div>
    </body>
    </html>
    '''


@app.route("/login", methods=["GET", "POST"])
def login():
    error = ""

    if request.method == "POST":
        email = request.form["email"].strip().lower()
        password = request.form["password"]

        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE email = ?", (email,))
        user = cur.fetchone()
        conn.close()

        if user and check_password_hash(user["password_hash"], password):
            session["user_id"] = user["id"]
            session["email"] = user["email"]
            return redirect(url_for("dashboard"))
        else:
            error = "Invalid email or password."

    error_html = f"<p class='error'>{error}</p>" if error else ""
    return f'''
    <html>
    <head>
      <title>Login</title>
      <style>
        body {{font-family:Arial; background:#fff;}}
        .container {{max-width:400px; margin:60px auto; padding:20px;
                     border:1px solid #ccc; border-radius:8px;}}
        .error {{color:red;}}
        input {{width:100%; padding:8px; margin-bottom:12px;}}
        button {{padding:8px 16px; background:#990000; color:#fff; border:none;
                 border-radius:4px; cursor:pointer;}}
        button:hover {{opacity:0.9;}}
        a {{color:#0066cc;}}
      </style>
    </head>
    <body>
      <div class="container">
        <h2>Login</h2>
        {error_html}
        <form method="post">
          <label>Miami Email:</label><br>
          <input type="email" name="email" placeholder="yourid@miamioh.edu" required>
          <label>Password:</label><br>
          <input type="password" name="password" placeholder="Password" required>
          <button type="submit">Login</button>
        </form>
        <p><a href="/register">Create an account</a></p>
      </div>
    </body>
    </html>
    '''


@app.route("/dashboard", methods=["GET", "POST"])
def dashboard():
    if "user_id" not in session:
        return redirect(url_for("login"))

    user_id = session["user_id"]
    conn = get_db()
    cur = conn.cursor()

    if request.method == "POST":
        new_ical = request.form["ical_url"].strip()
        cur.execute("UPDATE users SET ical_url = ? WHERE id = ?", (new_ical, user_id))
        conn.commit()

    cur.execute("SELECT email, ical_url FROM users WHERE id = ?", (user_id,))
    user = cur.fetchone()
    conn.close()

    email = user["email"]
    ical_url = user["ical_url"] or ""

    return f'''
    <html>
    <head>
      <title>Dashboard</title>
      <style>
        body {{font-family:Arial; background:#fff;}}
        .container {{max-width:500px; margin:60px auto; padding:20px;
                     border:1px solid #ccc; border-radius:8px;}}
        input {{width:100%; padding:8px; margin-bottom:12px;}}
        button {{padding:8px 16px; background:#990000; color:#fff; border:none;
                 border-radius:4px; cursor:pointer;}}
        button:hover {{opacity:0.9;}}
        a {{color:#0066cc;}}
      </style>
    </head>
    <body>
      <div class="container">
        <h2>Welcome, {email}</h2>
        <p><strong>Current iCal URL:</strong><br>{ical_url or "Not set"}</p>
        <h3>Update iCal URL</h3>
        <form method="post">
          <input type="url" name="ical_url" value="{ical_url}">
          <button type="submit">Save</button>
        </form>
        <p><a href="/chat">Go to chatbot</a></p>
        <p><a href="/logout">Logout</a></p>
      </div>
    </body>
    </html>
    '''


@app.route("/chat")
def chat():
    if "user_id" not in session:
        return redirect(url_for("login"))

    return '''
    <html>
    <head>
      <title>HelpDeskBot Chat</title>
      <style>
        body { font-family: Arial, sans-serif; background:#fff; margin:0; padding:0;}
        .container { max-width:600px; margin:60px auto; padding:20px; border:1px solid #ccc; border-radius:8px;}
        #chat-log { border:1px solid #ccc; padding:10px; height:250px; overflow-y:auto; }
        #msg { width:80%; padding:8px; }
        button { padding:8px 16px; background:#990000; color:#fff; border:none; border-radius:4px; cursor:pointer; }
        button:hover { opacity:0.9; }
        a { color:#0066cc; }
      </style>
    </head>
    <body>
      <div class="container">
        <h2>HelpDeskBot</h2>
        <div id="chat-log"></div>
        <br>
        <input id="msg" placeholder="Ask me something..." />
        <button onclick="sendMsg()">Send</button>
        <p><small>Try asking: <em>How many assignments do I have due this week?</em></small></p>
        <p><a href="/dashboard">Back to dashboard</a></p>
      </div>
      <script>
        async function sendMsg() {
          const input = document.getElementById('msg');
          const msg = input.value;
          if (!msg) return;

          const res = await fetch('/api/chat', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ message: msg })
          });

          const data = await res.json();
          const log = document.getElementById('chat-log');
          log.innerHTML += '<p><strong>You:</strong> ' + msg + '</p>';
          log.innerHTML += '<p><strong>Bot:</strong> ' + data.reply + '</p>';
          log.scrollTop = log.scrollHeight;
          input.value = '';
        }
      </script>
    </body>
    </html>
    '''


@app.route("/api/chat", methods=["POST"])
def api_chat():
    if "user_id" not in session:
        return jsonify({"reply": "Please log in so I can check your assignments."})

    data = request.get_json() or {}
    message = (data.get("message") or "").lower()

    # Get this user's iCal URL from the database
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT ical_url FROM users WHERE id = ?", (session["user_id"],))
    row = cur.fetchone()
    conn.close()

    if not row or not row["ical_url"]:
        return jsonify({"reply": "I don't have your calendar URL yet. Please add it on your dashboard."})

    ical_url = row["ical_url"]

    # Simple intent detection
    if "assignment" in message and "week" in message:
        try:
            count = count_events_this_week(ical_url)
            reply = f"You have {count} assignments due this week (Monday through Sunday)."
        except Exception:
            reply = "I had trouble reading your calendar. Please check that your iCal URL is correct."
    else:
        reply = "Right now I specialize in checking how many assignments you have due this week. Try asking that!"

    return jsonify({"reply": reply})


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))


# ---------------- MAIN ENTRY ---------------- #

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "initdb":
        init_db()
    else:
        app.run(debug=True)
