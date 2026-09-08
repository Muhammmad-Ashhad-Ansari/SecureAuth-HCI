import os
import re
import math
import hashlib
import secrets
import string
import sqlite3
import io
import base64
import time
from datetime import datetime, timedelta

from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import CSRFProtect
from dotenv import load_dotenv, set_key

import pyotp
import qrcode

# ============================================================
# APP SETUP
# ============================================================

ENV_PATH = os.path.join(os.path.dirname(__file__), ".env")
if not os.path.exists(ENV_PATH):
    open(ENV_PATH, "a").close()
load_dotenv(ENV_PATH)

if not os.environ.get("SECRET_KEY"):
    # generated once and persisted to .env — sessions now survive server restarts
    new_key = secrets.token_hex(32)
    set_key(ENV_PATH, "SECRET_KEY", new_key)
    os.environ["SECRET_KEY"] = new_key

app = Flask(__name__)
app.secret_key = os.environ["SECRET_KEY"]
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=15)  # idle timeout
csrf = CSRFProtect(app)

DB_PATH = "database.db"

# Lockout policy
MAX_OTP_ATTEMPTS = 5
OTP_LOCKOUT_SECONDS = 60
MAX_LOGIN_ATTEMPTS = 5
LOGIN_LOCKOUT_SECONDS = 60
BACKUP_CODE_COUNT = 10


# ============================================================
# DATABASE
# ============================================================

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            full_name TEXT NOT NULL,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            totp_secret TEXT NOT NULL,
            two_factor_enabled INTEGER NOT NULL DEFAULT 0,
            has_ever_setup_2fa INTEGER NOT NULL DEFAULT 0,
            last_totp_step INTEGER NOT NULL DEFAULT 0,
            session_version INTEGER NOT NULL DEFAULT 0,
            failed_attempts INTEGER NOT NULL DEFAULT 0,
            lockout_until REAL,
            login_failed_attempts INTEGER NOT NULL DEFAULT 0,
            login_lockout_until REAL,
            created_at TEXT NOT NULL
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS activity_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            event TEXT NOT NULL,
            success INTEGER NOT NULL,
            timestamp TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS backup_codes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            code_hash TEXT NOT NULL,
            used INTEGER NOT NULL DEFAULT 0,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS ip_lockouts (
            ip TEXT PRIMARY KEY,
            failed_attempts INTEGER NOT NULL DEFAULT 0,
            lockout_until REAL
        )
    """)
    conn.commit()
    conn.close()


def log_event(user_id, event, success):
    conn = get_db()
    conn.execute(
        "INSERT INTO activity_log (user_id, event, success, timestamp) VALUES (?, ?, ?, ?)",
        (user_id, event, 1 if success else 0, datetime.now().isoformat(timespec="seconds")),
    )
    conn.commit()
    conn.close()


def get_client_context():
    """Return only request data we can truthfully infer for visible sign-in context."""
    ua = (request.headers.get("User-Agent") or "").lower()
    if "windows" in ua:
        platform = "Windows"
    elif "android" in ua:
        platform = "Android"
    elif "iphone" in ua or "ipad" in ua:
        platform = "iOS"
    elif "macintosh" in ua or "mac os" in ua:
        platform = "macOS"
    elif "linux" in ua:
        platform = "Linux"
    else:
        platform = "Unknown device"

    if "edg/" in ua:
        browser = "Microsoft Edge"
    elif "firefox/" in ua:
        browser = "Firefox"
    elif "chrome/" in ua and "edg/" not in ua:
        browser = "Chrome"
    elif "safari/" in ua and "chrome/" not in ua:
        browser = "Safari"
    else:
        browser = "Browser"

    return {
        "platform": platform,
        "browser": browser,
        "ip": request.remote_addr or "Local network",
    }


def calculate_security_score(two_factor_enabled, codes_left, recent_failed=0):
    """Score durable account controls; surface recent events separately.

    A failed sign-in is an activity signal, not a configuration weakness, so it
    should not permanently reduce the user's protection score.
    """
    score = 40  # password protection
    if two_factor_enabled:
        score += 40
    if codes_left > 0:
        score += 20
    score = min(score, 100)
    label = "Excellent" if score >= 90 else "Strong" if score >= 75 else "Needs attention" if score >= 60 else "At risk"
    return score, label


# ============================================================
# BACKUP CODES
# ============================================================

def hash_code(code):
    return hashlib.sha256(code.encode()).hexdigest()


def generate_backup_codes(user_id):
    """Creates a fresh set of backup codes, replacing any existing ones."""
    conn = get_db()
    conn.execute("DELETE FROM backup_codes WHERE user_id = ?", (user_id,))
    plain_codes = []
    for _ in range(BACKUP_CODE_COUNT):
        code = "-".join(secrets.token_hex(2) for _ in range(2)).upper()  # e.g. A1B2-C3D4
        plain_codes.append(code)
        conn.execute(
            "INSERT INTO backup_codes (user_id, code_hash, used) VALUES (?, ?, 0)",
            (user_id, hash_code(code)),
        )
    conn.commit()
    conn.close()
    return plain_codes


def try_consume_backup_code(user_id, code):
    code = code.strip().upper()
    conn = get_db()
    row = conn.execute(
        "SELECT id FROM backup_codes WHERE user_id = ? AND code_hash = ? AND used = 0",
        (user_id, hash_code(code)),
    ).fetchone()
    if not row:
        conn.close()
        return False
    conn.execute("UPDATE backup_codes SET used = 1 WHERE id = ?", (row["id"],))
    conn.commit()
    conn.close()
    return True


def remaining_backup_codes(user_id):
    conn = get_db()
    count = conn.execute(
        "SELECT COUNT(*) AS c FROM backup_codes WHERE user_id = ? AND used = 0", (user_id,)
    ).fetchone()["c"]
    conn.close()
    return count


# ============================================================
# TOTP REPLAY PREVENTION
# ============================================================
#
# pyotp.verify(valid_window=1) only checks that a code matches SOME step within
# the window — it happily accepts the same valid code twice in a row. We track
# the last time-step that was successfully used per user and refuse to accept
# that step (or any earlier one) again, so a captured/replayed code is rejected
# even while it's still numerically "current".

def verify_totp_no_replay(user, code):
    """Returns the matched time-step (int) on success, or None if invalid/replayed."""
    if not code:
        return None
    totp = pyotp.TOTP(user["totp_secret"])
    current_step = int(time.time()) // 30
    last_used = user["last_totp_step"] or 0
    for offset in (0, -1, 1):
        step = current_step + offset
        if step <= last_used:
            continue  # already used or older than the last accepted code — reject as a replay
        candidate = totp.generate_otp(step)
        if secrets.compare_digest(candidate, code.strip()):
            return step
    return None


def mark_totp_step_used(user_id, step):
    conn = get_db()
    # only ever advances forward, in case of any out-of-order requests
    conn.execute(
        "UPDATE users SET last_totp_step = MAX(last_totp_step, ?) WHERE id = ?",
        (step, user_id),
    )
    conn.commit()
    conn.close()


# ============================================================
# LOCKOUT HELPERS
# ============================================================

def is_locked_out(until_value):
    return bool(until_value and until_value > time.time())


def register_failed_otp(user_id):
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    attempts = user["failed_attempts"] + 1
    lockout_until = None
    newly_locked = False
    if attempts >= MAX_OTP_ATTEMPTS:
        lockout_until = time.time() + OTP_LOCKOUT_SECONDS
        attempts = 0
        newly_locked = True
    conn.execute(
        "UPDATE users SET failed_attempts = ?, lockout_until = ? WHERE id = ?",
        (attempts, lockout_until, user_id),
    )
    conn.commit()
    conn.close()
    if newly_locked:
        log_event(user_id, "Account locked", False)


def reset_failed_otp(user_id):
    conn = get_db()
    conn.execute(
        "UPDATE users SET failed_attempts = 0, lockout_until = NULL WHERE id = ?",
        (user_id,),
    )
    conn.commit()
    conn.close()


def register_failed_login(user_id):
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    attempts = user["login_failed_attempts"] + 1
    lockout_until = None
    newly_locked = False
    if attempts >= MAX_LOGIN_ATTEMPTS:
        lockout_until = time.time() + LOGIN_LOCKOUT_SECONDS
        attempts = 0
        newly_locked = True
    conn.execute(
        "UPDATE users SET login_failed_attempts = ?, login_lockout_until = ? WHERE id = ?",
        (attempts, lockout_until, user_id),
    )
    conn.commit()
    conn.close()
    if newly_locked:
        log_event(user_id, "Account locked", False)


def reset_failed_login(user_id):
    conn = get_db()
    conn.execute(
        "UPDATE users SET login_failed_attempts = 0, login_lockout_until = NULL WHERE id = ?",
        (user_id,),
    )
    conn.commit()
    conn.close()


# ============================================================
# IP-BASED RATE LIMITING
# ============================================================
# Separate from the per-account lockout above. Per-account protects a single
# username from brute force; this protects against one source hammering many
# different usernames (or hammering OTP attempts) from the same IP.

MAX_IP_ATTEMPTS = 15
IP_LOCKOUT_SECONDS = 120


def get_ip_lockout(ip):
    conn = get_db()
    row = conn.execute("SELECT * FROM ip_lockouts WHERE ip = ?", (ip,)).fetchone()
    conn.close()
    return row


def is_ip_locked_out(ip):
    row = get_ip_lockout(ip)
    return bool(row and is_locked_out(row["lockout_until"]))


def register_failed_ip(ip):
    conn = get_db()
    row = conn.execute("SELECT * FROM ip_lockouts WHERE ip = ?", (ip,)).fetchone()
    attempts = (row["failed_attempts"] if row else 0) + 1
    lockout_until = None
    newly_locked = False
    if attempts >= MAX_IP_ATTEMPTS:
        lockout_until = time.time() + IP_LOCKOUT_SECONDS
        attempts = 0
        newly_locked = True
    conn.execute(
        """INSERT INTO ip_lockouts (ip, failed_attempts, lockout_until) VALUES (?, ?, ?)
           ON CONFLICT(ip) DO UPDATE SET failed_attempts = excluded.failed_attempts,
           lockout_until = excluded.lockout_until""",
        (ip, attempts, lockout_until),
    )
    conn.commit()
    conn.close()
    if newly_locked:
        log_event(None, f"IP locked ({ip})", False)


def reset_failed_ip(ip):
    conn = get_db()
    conn.execute(
        "UPDATE ip_lockouts SET failed_attempts = 0, lockout_until = NULL WHERE ip = ?",
        (ip,),
    )
    conn.commit()
    conn.close()


def login_required(view):
    def wrapped(*args, **kwargs):
        if not session.get("authenticated"):
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    wrapped.__name__ = view.__name__
    return wrapped


@app.before_request
def enforce_session_validity():
    # session_version check: if the account's password was changed or the user
    # clicked "log out other sessions", any session carrying an older version
    # number is treated as revoked, even though its signed cookie is still valid.
    if session.get("authenticated"):
        conn = get_db()
        row = conn.execute(
            "SELECT session_version FROM users WHERE id = ?", (session.get("user_id"),)
        ).fetchone()
        conn.close()
        if not row or row["session_version"] != session.get("session_version"):
            session.clear()
            return

        # Any authenticated session is refreshed on activity; Flask's signed cookie
        # + PERMANENT_SESSION_LIFETIME already expires it after 15 idle minutes.
        session.permanent = True
        session.modified = True


# ============================================================
# AUTH ROUTES
# ============================================================

@app.route("/")
def landing():
    if session.get("authenticated"):
        return redirect(url_for("dashboard"))
    return render_template("landing.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html")

    data = request.form
    full_name = data.get("full_name", "").strip()
    username = data.get("username", "").strip().lower()
    password = data.get("password", "")
    confirm = data.get("confirm_password", "")

    if not full_name or not username or not password:
        return render_template("register.html", error="All fields are required.")
    if len(username) < 3:
        return render_template("register.html", error="Username must be at least 3 characters.")
    if password != confirm:
        return render_template("register.html", error="Passwords do not match.")
    if len(password) < 8:
        return render_template("register.html", error="Password must be at least 8 characters.")

    conn = get_db()
    existing = conn.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
    if existing:
        conn.close()
        return render_template("register.html", error="That username is already taken.")

    password_hash = generate_password_hash(password)
    # Stored as plain text — in a production system this would be encrypted at
    # rest (e.g. via a KMS-managed key), left out of scope for this lab project.
    totp_secret = pyotp.random_base32()

    cur = conn.execute(
        """INSERT INTO users (full_name, username, password_hash, totp_secret,
           two_factor_enabled, failed_attempts, login_failed_attempts, created_at)
           VALUES (?, ?, ?, ?, 0, 0, 0, ?)""",
        (full_name, username, password_hash, totp_secret, datetime.now().isoformat(timespec="seconds")),
    )
    conn.commit()
    user_id = cur.lastrowid
    conn.close()

    session.clear()
    session["setup_user_id"] = user_id
    return redirect(url_for("setup_2fa"))


def _render_setup_2fa(user, error=None):
    totp = pyotp.TOTP(user["totp_secret"])
    otpauth_uri = totp.provisioning_uri(name=user["username"], issuer_name="SecureAuth")
    qr = qrcode.QRCode(box_size=8, border=2)
    qr.add_data(otpauth_uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color="#0f1626", back_color="#e8edf7")
    buf = io.BytesIO()
    try:
        img.save(buf, format="PNG")
    except TypeError:
        # qrcode's pure-Python PNG factory does not accept Pillow's
        # optional ``format`` keyword, but writes the same PNG bytes.
        img.save(buf)
    qr_base64 = base64.b64encode(buf.getvalue()).decode()
    return render_template(
        "setup_2fa.html",
        qr_base64=qr_base64,
        secret=user["totp_secret"],
        username=user["username"],
        error=error,
    )


@app.route("/setup-2fa", methods=["GET", "POST"])
def setup_2fa():
    setup_user_id = session.get("setup_user_id")
    reenable_user_id = session.get("reenable_2fa_user_id")
    user_id = setup_user_id or reenable_user_id
    if not user_id:
        return redirect(url_for("login"))

    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()

    if request.method == "GET":
        return _render_setup_2fa(user)

    code = request.form.get("otp", "").strip()
    step = verify_totp_no_replay(user, code)

    if step is not None:
        mark_totp_step_used(user_id, step)
        conn = get_db()
        conn.execute(
            "UPDATE users SET two_factor_enabled = 1, has_ever_setup_2fa = 1 WHERE id = ?",
            (user_id,),
        )
        conn.commit()
        conn.close()
        log_event(user_id, "2FA enabled", True)

        codes = generate_backup_codes(user_id)
        if reenable_user_id:
            # user was already fully authenticated (re-enabling from settings) —
            # keep their session alive, don't force them back through login
            session.pop("reenable_2fa_user_id", None)
            session["show_backup_codes_user_id"] = user_id
            session["backup_codes_plain"] = codes
            session["backup_codes_return_to"] = "settings"
        else:
            session.clear()
            session["show_backup_codes_user_id"] = user_id
            session["backup_codes_plain"] = codes
        return redirect(url_for("backup_codes"))

    log_event(user_id, "2FA setup verification", False)
    return _render_setup_2fa(user, error="Invalid code. Check your authenticator app and try again.")


@app.route("/backup-codes")
def backup_codes():
    user_id = session.get("show_backup_codes_user_id")
    codes = session.get("backup_codes_plain")
    if not user_id or not codes:
        return redirect(url_for("login"))
    return render_template("backup_codes.html", codes=codes)


@app.route("/backup-codes/acknowledge", methods=["POST"])
def acknowledge_backup_codes():
    return_to = session.pop("backup_codes_return_to", None)
    session.pop("show_backup_codes_user_id", None)
    session.pop("backup_codes_plain", None)
    if return_to == "settings":
        return redirect(url_for("settings"))
    if return_to == "dashboard":
        return redirect(url_for("dashboard"))
    return redirect(url_for("login", setup="done"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html", just_setup=request.args.get("setup") == "done")

    client_ip = request.remote_addr
    if is_ip_locked_out(client_ip):
        row = get_ip_lockout(client_ip)
        remaining = int(row["lockout_until"] - time.time())
        return render_template("login.html", locked=True, remaining=max(remaining, 1))

    username = request.form.get("username", "").strip().lower()
    password = request.form.get("password", "")

    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    conn.close()

    if user and is_locked_out(user["login_lockout_until"]):
        remaining = int(user["login_lockout_until"] - time.time())
        return render_template("login.html", locked=True, remaining=max(remaining, 1))

    # Generic error for both "no such user" and "wrong password" — don't leak which one
    if not user or not check_password_hash(user["password_hash"], password):
        register_failed_ip(client_ip)
        if is_ip_locked_out(client_ip):
            row = get_ip_lockout(client_ip)
            remaining = int(row["lockout_until"] - time.time())
            return render_template("login.html", locked=True, remaining=max(remaining, 1))
        if user:
            register_failed_login(user["id"])
            log_event(user["id"], "Password authentication failed", False)
            conn = get_db()
            refreshed = conn.execute("SELECT * FROM users WHERE id = ?", (user["id"],)).fetchone()
            conn.close()
            if is_locked_out(refreshed["login_lockout_until"]):
                remaining = int(refreshed["login_lockout_until"] - time.time())
                return render_template("login.html", locked=True, remaining=max(remaining, 1))
        return render_template("login.html", error="Invalid username or password.")

    reset_failed_login(user["id"])
    reset_failed_ip(client_ip)

    if not user["two_factor_enabled"]:
        if not user["has_ever_setup_2fa"]:
            # brand-new account — 2FA setup is mandatory before first use
            session.clear()
            session["setup_user_id"] = user["id"]
            return redirect(url_for("setup_2fa"))

        # 2FA was deliberately turned off in settings — password alone is enough
        session.clear()
        session["authenticated"] = True
        session["user_id"] = user["id"]
        session["username"] = user["username"]
        session["session_version"] = user["session_version"]
        session["login_at"] = datetime.now().isoformat(timespec="minutes")
        session["auth_method"] = "Password"
        log_event(user["id"], "Login successful", True)
        return redirect(url_for("dashboard", verified="password"))

    session.clear()
    session["pending_user_id"] = user["id"]
    log_event(user["id"], "Password verified", True)
    return redirect(url_for("verify_otp"))


@app.route("/verify-otp", methods=["GET", "POST"])
def verify_otp():
    user_id = session.get("pending_user_id")
    if not user_id:
        return redirect(url_for("login"))

    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()

    if not user:
        session.clear()
        return redirect(url_for("login"))

    if is_locked_out(user["lockout_until"]):
        remaining = int(user["lockout_until"] - time.time())
        return render_template("verify_otp.html", locked=True, remaining=max(remaining, 1), client_context=get_client_context())

    client_ip = request.remote_addr
    if is_ip_locked_out(client_ip):
        row = get_ip_lockout(client_ip)
        remaining = int(row["lockout_until"] - time.time())
        return render_template("verify_otp.html", locked=True, remaining=max(remaining, 1), client_context=get_client_context())

    if request.method == "GET":
        return render_template("verify_otp.html", locked=False, client_context=get_client_context())

    code = request.form.get("otp", "").strip()
    use_backup = request.form.get("mode") == "backup"

    if use_backup:
        verified = try_consume_backup_code(user_id, code)
        totp_step = None
    else:
        totp_step = verify_totp_no_replay(user, code)
        verified = totp_step is not None

    if verified:
        if totp_step is not None:
            mark_totp_step_used(user_id, totp_step)
        reset_failed_otp(user_id)
        reset_failed_ip(client_ip)
        log_event(user_id, "Backup code used" if use_backup else "OTP successful", True)

        session.clear()
        session["authenticated"] = True
        session["user_id"] = user_id
        session["username"] = user["username"]
        session["session_version"] = user["session_version"]
        session["login_at"] = datetime.now().isoformat(timespec="minutes")
        session["auth_method"] = "Backup code" if use_backup else "Authenticator code"
        log_event(user_id, "Login successful", True)
        return redirect(url_for("dashboard", verified="1"))

    register_failed_otp(user_id)
    register_failed_ip(client_ip)
    log_event(user_id, "Backup code failed" if use_backup else "OTP failed", False)

    conn = get_db()
    refreshed = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()
    if is_locked_out(refreshed["lockout_until"]):
        remaining = int(refreshed["lockout_until"] - time.time())
        return render_template("verify_otp.html", locked=True, remaining=max(remaining, 1), client_context=get_client_context())

    error = "Invalid backup code. Check it and try an unused code." if use_backup else "Invalid code. Check your authenticator app and enter the newest 6-digit code."
    return render_template("verify_otp.html", locked=False, error=error, backup_mode=use_backup, client_context=get_client_context())


@app.route("/logout")
def logout():
    if session.get("user_id"):
        log_event(session["user_id"], "Logout", True)
    session.clear()
    return redirect(url_for("landing"))


@app.route("/dashboard")
@login_required
def dashboard():
    conn = get_db()
    user = conn.execute("SELECT two_factor_enabled FROM users WHERE id = ?", (session["user_id"],)).fetchone()
    events = conn.execute(
        "SELECT event, success, timestamp FROM activity_log WHERE user_id = ? ORDER BY id DESC LIMIT 8",
        (session["user_id"],),
    ).fetchall()
    failed_recent = conn.execute(
        "SELECT COALESCE(SUM(CASE WHEN success = 0 THEN 1 ELSE 0 END), 0) AS c "
        "FROM (SELECT success FROM activity_log WHERE user_id = ? ORDER BY id DESC LIMIT 8)",
        (session["user_id"],),
    ).fetchone()["c"]
    conn.close()
    codes_left = remaining_backup_codes(session["user_id"])
    two_factor_enabled = bool(user["two_factor_enabled"])
    security_score, security_label = calculate_security_score(two_factor_enabled, codes_left, failed_recent)
    return render_template(
        "dashboard.html",
        username=session["username"],
        events=events,
        codes_left=codes_left,
        two_factor_enabled=two_factor_enabled,
        security_score=security_score,
        security_label=security_label,
        failed_recent=failed_recent,
        client_context=get_client_context(),
        login_at=session.get("login_at"),
        auth_method=session.get("auth_method", "Verified session"),
        just_verified=request.args.get("verified"),
    )


@app.route("/activity")
@login_required
def activity():
    conn = get_db()
    events = conn.execute(
        "SELECT event, success, timestamp FROM activity_log WHERE user_id = ? ORDER BY id DESC LIMIT 100",
        (session["user_id"],),
    ).fetchall()
    conn.close()
    return render_template("activity.html", events=events, client_context=get_client_context())


@app.route("/account/regenerate-backup-codes", methods=["POST"])
@login_required
def regenerate_backup_codes():
    codes = generate_backup_codes(session["user_id"])
    log_event(session["user_id"], "Backup codes regenerated", True)
    session["show_backup_codes_user_id"] = session["user_id"]
    session["backup_codes_plain"] = codes
    session["backup_codes_return_to"] = "settings"
    return redirect(url_for("backup_codes"))


def bump_session_version(user_id):
    """Invalidates every other session for this user. Returns the new version
    number so the caller can update the current session and stay logged in."""
    conn = get_db()
    conn.execute("UPDATE users SET session_version = session_version + 1 WHERE id = ?", (user_id,))
    new_version = conn.execute(
        "SELECT session_version FROM users WHERE id = ?", (user_id,)
    ).fetchone()["session_version"]
    conn.commit()
    conn.close()
    return new_version


@app.route("/settings")
@login_required
def settings():
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone()
    conn.close()
    codes_left = remaining_backup_codes(session["user_id"])
    return render_template(
        "settings.html",
        two_factor_enabled=bool(user["two_factor_enabled"]),
        codes_left=codes_left,
        client_context=get_client_context(),
        login_at=session.get("login_at"),
        auth_method=session.get("auth_method", "Verified session"),
    )


@app.route("/settings/change-password", methods=["POST"])
@login_required
def change_password():
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone()

    current_password = request.form.get("current_password", "")
    new_password = request.form.get("new_password", "")
    confirm_password = request.form.get("confirm_new_password", "")

    error = None
    if not check_password_hash(user["password_hash"], current_password):
        error = "Current password is incorrect."
    elif len(new_password) < 8:
        error = "New password must be at least 8 characters."
    elif new_password != confirm_password:
        error = "New passwords do not match."

    if error:
        conn.close()
        codes_left = remaining_backup_codes(session["user_id"])
        return render_template(
            "settings.html",
            two_factor_enabled=bool(user["two_factor_enabled"]),
            codes_left=codes_left,
            password_error=error,
            client_context=get_client_context(),
            login_at=session.get("login_at"),
            auth_method=session.get("auth_method", "Verified session"),
        )

    new_hash = generate_password_hash(new_password)
    conn.execute("UPDATE users SET password_hash = ? WHERE id = ?", (new_hash, session["user_id"]))
    conn.commit()
    conn.close()

    log_event(session["user_id"], "Password changed", True)

    # changing the password invalidates every other logged-in session
    new_version = bump_session_version(session["user_id"])
    session["session_version"] = new_version

    codes_left = remaining_backup_codes(session["user_id"])
    return render_template(
        "settings.html",
        two_factor_enabled=True,
        codes_left=codes_left,
        password_success="Password updated. You've been kept signed in here; any other active sessions were signed out.",
        client_context=get_client_context(),
        login_at=session.get("login_at"),
        auth_method=session.get("auth_method", "Verified session"),
    )


@app.route("/settings/enable-2fa", methods=["POST"])
@login_required
def enable_2fa():
    # regenerate the secret so re-enabling always means a fresh QR + fresh codes,
    # never silently reactivating a secret that may be stale
    new_secret = pyotp.random_base32()
    conn = get_db()
    conn.execute("UPDATE users SET totp_secret = ?, last_totp_step = 0 WHERE id = ?",
                 (new_secret, session["user_id"]))
    conn.commit()
    conn.close()
    session["reenable_2fa_user_id"] = session["user_id"]
    return redirect(url_for("setup_2fa"))


@app.route("/settings/disable-2fa", methods=["POST"])
@login_required
def disable_2fa():
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone()

    password = request.form.get("current_password", "")
    code = request.form.get("otp", "").strip()

    valid_password = check_password_hash(user["password_hash"], password)
    totp_step = verify_totp_no_replay(user, code) if valid_password else None

    if not valid_password or totp_step is None:
        conn.close()
        codes_left = remaining_backup_codes(session["user_id"])
        return render_template(
            "settings.html",
            two_factor_enabled=True,
            codes_left=codes_left,
            disable_error="Incorrect password or authentication code.",
            client_context=get_client_context(),
            login_at=session.get("login_at"),
            auth_method=session.get("auth_method", "Verified session"),
        )

    mark_totp_step_used(session["user_id"], totp_step)
    conn.execute("UPDATE users SET two_factor_enabled = 0 WHERE id = ?", (session["user_id"],))
    conn.execute("DELETE FROM backup_codes WHERE user_id = ?", (session["user_id"],))
    conn.commit()
    conn.close()

    log_event(session["user_id"], "2FA disabled", True)
    return redirect(url_for("settings"))


@app.route("/settings/logout-other-sessions", methods=["POST"])
@login_required
def logout_other_sessions():
    new_version = bump_session_version(session["user_id"])
    session["session_version"] = new_version  # keep the current session alive
    log_event(session["user_id"], "Logged out other sessions", True)
    return redirect(url_for("settings"))


@app.route("/vault")
@login_required
def vault():
    return render_template("index.html")


# ============================================================
# PASSWORD SECURITY SUITE (same logic as before, now behind auth;
# /check-strength stays public+CSRF-exempt for the registration form)
# ============================================================

COMMON_PASSWORDS = {
    "password", "password1", "password123", "password1234", "passw0rd", "pass",
    "123456", "1234567", "12345678", "123456789", "1234567890", "12345678901",
    "12345", "1234", "123123", "123321", "654321", "111111", "222222", "333333",
    "000000", "112233", "121212", "696969", "666666", "777777", "888888", "999999",
    "qwerty", "qwerty123", "qwertyuiop", "qwe123", "asdfgh", "asdfghjkl", "zxcvbn",
    "zxcvbnm", "123qwe", "qazwsx", "1qaz2wsx", "1q2w3e4r", "abc123", "abcdef",
    "admin", "administrator", "root", "toor", "guest", "user", "test", "test123",
    "letmein", "letmein1", "welcome", "welcome1", "monkey", "monkey123", "dragon",
    "dragon123", "master", "master123", "login", "login123", "princess",
    "football", "soccer", "baseball", "basketball", "iloveyou", "lovely",
    "sunshine", "sunset", "trustno1", "secret", "secret123", "hello", "hello123",
    "computer", "whatever", "freedom", "ninja", "shadow", "shadow123", "superman",
    "batman", "starwars", "pokemon", "mickey", "killer", "hunter", "harley",
    "flower", "pepper", "cookie", "cheese", "ginger", "matrix", "mustang",
    "peanut", "summer", "winter", "autumn", "spring", "charlie", "daniel",
    "andrew", "thomas", "joshua", "michael", "robert", "jordan", "jessica",
    "ashley", "hannah", "phoenix", "tigger", "bubble", "purple", "orange",
    "blue", "green", "red", "yellow", "silver", "gold",
}

SEQUENTIAL_PATTERNS = [
    "0123456789", "9876543210",
    "abcdefghijklmnopqrstuvwxyz",
    "zyxwvutsrqponmlkjihgfedcba",
    "qwertyuiop", "asdfghjkl", "zxcvbnm"
]

KEYBOARD_PATTERNS = [
    "qwertyuiop", "asdfghjkl", "zxcvbnm",
    "poiuytrewq", "lkjhgfdsa", "mnbvcxz",
    "1qaz", "2wsx", "3edc", "4rfv", "5tgb", "6yhn", "7ujm", "8ik,", "9ol.", "0p;/",
    "zaq1", "xsw2", "cde3", "vfr4", "bgt5", "nhy6", "mju7", ",ki8", ".lo9", "/;p0",
]

AMBIGUOUS_CHARS = set("Il1O0o`'\"|:;,.<>?/\\~")

PASSPHRASE_WORDS = [
    "acorn", "aero", "alpine", "amber", "amethyst", "anchor", "apricot",
    "aqua", "arcade", "arctic", "arena", "arrow", "aspen", "atlas", "aurora",
    "autumn", "azure", "bamboo", "basalt", "bayou", "beacon", "birch",
    "bison", "blaze", "bloom", "blossom", "bonfire", "bonsai", "breeze",
    "briar", "brick", "bright", "cactus", "canyon", "carbon", "cascade",
    "cedar", "chalice", "charcoal", "cherry", "cinder", "cirrus", "clover",
    "cobalt", "comet", "copper", "coral", "cosmos", "cotton", "crest",
    "crimson", "crystal", "cypress", "dawn", "delta", "denim", "desert",
    "diorite", "dune", "dusk", "echo", "eclipse", "ember", "emerald",
    "falcon", "feather", "fern", "fjord", "flint", "foam", "forest", "fossil",
    "foxglove", "frost", "galaxy", "gale", "garnet", "geode", "glacier",
    "glade", "glass", "gleam", "goldfinch", "granite", "gravel", "grove",
    "gull", "harbor", "haze", "hazel", "heather", "heron", "hickory",
    "hilltop", "horizon", "hyacinth", "ibis", "icicle", "indigo", "iris",
    "island", "ivy", "jade", "jasmine", "juniper", "kelp", "kestrel",
    "kingfisher", "lagoon", "lantern", "lapis", "lava", "lemon", "lichen",
    "lilac", "linden", "lodge", "lotus", "lumen", "lychee", "magma",
    "magnolia", "maple", "marble", "marsh", "meadow", "melody", "mesa",
    "meteor", "mica", "mist", "monsoon", "moss", "mountain", "mulberry",
    "nebula", "nectar", "neon", "nickel", "nightshade", "noon", "north",
    "nova", "oasis", "ocean", "olive", "onyx", "opal", "orbit", "orchid",
    "osprey", "otter", "owl", "oxbow", "palm", "panda", "papaya", "paradise",
    "peacock", "pearl", "pecan", "pelican", "petal", "phantom", "phoenix",
    "pine", "plum", "pond", "poplar", "poppy", "prism", "puma", "pyrite",
    "quartz", "quail", "queen", "quill", "raccoon", "rainbow", "raven",
    "reef", "ridge", "rill", "river", "robin", "rose", "ruby", "runner",
    "sable", "safari", "salmon", "sand", "sapphire", "satin", "savanna",
    "scarlet", "sea", "serene", "shadow", "shale", "shell", "shoal", "silk",
    "silver", "slate", "smoke", "snow", "solstice", "sparrow", "spire",
    "spruce", "starling", "stone", "storm", "summit", "sunbird", "sunrise",
    "sunset", "swan", "talon", "tangerine", "temple", "thistle", "tide",
    "timber", "topaz", "torch", "tornado", "trail", "trellis", "trident",
    "tundra", "turtle", "valley", "vapor", "veil", "velvet", "verdant",
    "vertex", "vista", "volcano", "willow", "winter", "wolf", "zephyr",
]

MAX_POINTS = 8


def has_sequential_chars(password, run_length=4):
    pw_lower = password.lower()
    for pattern in SEQUENTIAL_PATTERNS:
        for i in range(len(pattern) - run_length + 1):
            if pattern[i:i + run_length] in pw_lower:
                return True
    return False


def has_keyboard_pattern(password, run_length=4):
    pw_lower = password.lower()
    for pattern in KEYBOARD_PATTERNS:
        for i in range(len(pattern) - run_length + 1):
            if pattern[i:i + run_length] in pw_lower:
                return True
    return False


def has_repeated_chars(password, run_length=3):
    for i in range(len(password) - run_length + 1):
        if len(set(password[i:i + run_length])) == 1:
            return True
    return False


def has_obvious_date(password):
    if re.search(r'19[5-9]\d|20[0-2]\d', password):
        return True
    if re.search(r'\d{1,2}[/\-.]\d{1,2}[/\-.]\d{2,4}', password):
        return True
    return False


def calculate_entropy(password):
    pool = 0
    if re.search(r'[a-z]', password):
        pool += 26
    if re.search(r'[A-Z]', password):
        pool += 26
    if re.search(r'[0-9]', password):
        pool += 10
    if re.search(r'[^a-zA-Z0-9]', password):
        pool += 32
    if pool == 0:
        return 0
    entropy = len(password) * math.log2(pool)
    return round(entropy, 2)


def estimate_crack_time(entropy_bits):
    guesses_per_second = 1e10
    total_combinations = 2 ** entropy_bits
    seconds = total_combinations / (2 * guesses_per_second)

    minute, hour, day = 60, 3600, 86400
    month, year, decade, century = day * 30, day * 365, day * 365 * 10, day * 365 * 100

    if seconds < 1:
        return "Instantly"
    if seconds < minute:
        return f"{seconds:.0f} seconds"
    if seconds < hour:
        return f"{seconds / minute:.0f} minutes"
    if seconds < day:
        return f"{seconds / hour:.1f} hours"
    if seconds < month:
        return f"{seconds / day:.1f} days"
    if seconds < year:
        return f"{seconds / month:.1f} months"
    if seconds < decade:
        return f"{seconds / decade:.1f} decades"
    return "Centuries"


def password_fingerprint(password):
    if not password:
        return ""
    h = hashlib.sha256(password.encode()).hexdigest()
    return " ".join(h[i:i + 4] for i in range(0, 24, 4)) + "  …"


def char_composition(password):
    return {
        "uppercase": len(re.findall(r'[A-Z]', password)),
        "lowercase": len(re.findall(r'[a-z]', password)),
        "digits": len(re.findall(r'[0-9]', password)),
        "special": len(re.findall(r'[^a-zA-Z0-9]', password)),
    }


def analyze_password(password):
    if not password:
        return {
            "score": 0,
            "label": "No Password",
            "entropy": 0,
            "crack_time": "N/A",
            "checks": [],
            "suggestions": ["Start typing a password to see its strength."],
            "composition": char_composition(""),
            "fingerprint": "",
        }

    checks = []
    suggestions = []
    points = 0

    length = len(password)
    if length >= 12:
        checks.append({"label": "Length (12+ characters)", "passed": True})
        points += 2
    elif length >= 8:
        checks.append({"label": "Length (8+ characters)", "passed": True})
        points += 1
        suggestions.append("Use 12+ characters for stronger protection.")
    else:
        checks.append({"label": "Length (minimum 8 characters)", "passed": False})
        suggestions.append("Password is too short — use at least 8 characters.")

    has_upper = bool(re.search(r'[A-Z]', password))
    checks.append({"label": "Contains uppercase letter", "passed": has_upper})
    if has_upper:
        points += 1
    else:
        suggestions.append("Add at least one uppercase letter (A-Z).")

    has_lower = bool(re.search(r'[a-z]', password))
    checks.append({"label": "Contains lowercase letter", "passed": has_lower})
    if has_lower:
        points += 1
    else:
        suggestions.append("Add at least one lowercase letter (a-z).")

    has_digit = bool(re.search(r'[0-9]', password))
    checks.append({"label": "Contains a digit", "passed": has_digit})
    if has_digit:
        points += 1
    else:
        suggestions.append("Add at least one number (0-9).")

    has_special = bool(re.search(r'[^a-zA-Z0-9]', password))
    checks.append({"label": "Contains special character", "passed": has_special})
    if has_special:
        points += 1
    else:
        suggestions.append("Add a special character (e.g. ! @ # $ %).")

    is_common = password.lower() in COMMON_PASSWORDS
    checks.append({"label": "Not a commonly used / leaked password", "passed": not is_common})
    if not is_common:
        points += 1
    else:
        suggestions.append("This is a widely known/leaked password — avoid it entirely.")

    is_sequential = has_sequential_chars(password)
    is_keyboard = has_keyboard_pattern(password)
    is_repeated = has_repeated_chars(password)
    has_pattern = is_sequential or is_keyboard or is_repeated
    checks.append({"label": "No sequential / keyboard / repeated patterns", "passed": not has_pattern})
    if not has_pattern:
        points += 0.5
    else:
        suggestions.append("Avoid sequences ('abcd', '1234'), keyboard walks ('1qaz'), or repeats ('aaaa').")

    is_date = has_obvious_date(password)
    checks.append({"label": "No obvious dates / birth years", "passed": not is_date})
    if not is_date:
        points += 0.5
    else:
        suggestions.append("Avoid birth years and date patterns (e.g. '1990', '12-09-1988').")

    entropy = calculate_entropy(password)
    crack_time = estimate_crack_time(entropy)

    rule_score = (points / MAX_POINTS) * 60
    entropy_score = min(entropy / 80, 1) * 40
    final_score = round(rule_score + entropy_score)
    final_score = max(0, min(100, final_score))

    if is_common:
        final_score = min(final_score, 15)

    if final_score >= 80:
        label = "Very Strong"
    elif final_score >= 60:
        label = "Strong"
    elif final_score >= 35:
        label = "Medium"
    elif final_score >= 15:
        label = "Weak"
    else:
        label = "Very Weak"

    if not suggestions:
        suggestions.append("Great job! This password follows all recommended practices.")

    return {
        "score": final_score,
        "label": label,
        "entropy": entropy,
        "crack_time": crack_time,
        "checks": checks,
        "suggestions": suggestions,
        "composition": char_composition(password),
        "fingerprint": password_fingerprint(password),
    }


def generate_password(length=16, use_upper=True, use_lower=True, use_digits=True,
                      use_special=True, exclude_ambiguous=False):
    pools = []
    if use_lower:
        pools.append(string.ascii_lowercase)
    if use_upper:
        pools.append(string.ascii_uppercase)
    if use_digits:
        pools.append(string.digits)
    if use_special:
        pools.append("!@#$%^&*()-_=+[]{}?")

    if not pools:
        return {"error": "Select at least one character type."}

    if exclude_ambiguous:
        for i, p in enumerate(pools):
            if any(ch.isalnum() for ch in p):
                pools[i] = "".join(c for c in p if c not in AMBIGUOUS_CHARS)
        pools = [p for p in pools if p]
        if not pools:
            return {"error": "Ambiguous-exclusion removed every selected character type."}

    length = max(4, min(length, 128))

    password_chars = [secrets.choice(pool) for pool in pools]
    all_chars = "".join(pools)
    password_chars += [secrets.choice(all_chars) for _ in range(length - len(password_chars))]

    for i in range(len(password_chars) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        password_chars[i], password_chars[j] = password_chars[j], password_chars[i]

    password = "".join(password_chars)
    return {"password": password, "analysis": analyze_password(password)}


def generate_passphrase(num_words=5, separator="-", capitalize=True, add_digit=False):
    num_words = max(3, min(num_words, 10))
    separator = separator if separator in ("-", ".", "_", " ") else "-"

    chosen = [secrets.choice(PASSPHRASE_WORDS) for _ in range(num_words)]
    if capitalize:
        chosen = [w.capitalize() for w in chosen]
    phrase = separator.join(chosen)
    if add_digit:
        phrase += str(secrets.randbelow(10))

    return {"password": phrase, "analysis": analyze_password(phrase)}


@app.route('/check-strength', methods=['POST'])
@csrf.exempt  # public, stateless, unauthenticated — used live on the registration form
def check_strength():
    data = request.get_json() or {}
    password = data.get('password', '')
    return jsonify(analyze_password(password))


@app.route('/analyze', methods=['POST'])
@login_required
@csrf.exempt  # stateless JSON API called from the authenticated vault page only
def analyze():
    data = request.get_json() or {}
    password = data.get('password', '')
    return jsonify(analyze_password(password))


@app.route('/generate', methods=['POST'])
@login_required
@csrf.exempt
def generate():
    data = request.get_json() or {}
    length = int(data.get('length', 16))
    use_upper = bool(data.get('use_upper', True))
    use_lower = bool(data.get('use_lower', True))
    use_digits = bool(data.get('use_digits', True))
    use_special = bool(data.get('use_special', True))
    exclude_ambiguous = bool(data.get('exclude_ambiguous', False))

    result = generate_password(length, use_upper, use_lower, use_digits,
                               use_special, exclude_ambiguous)
    if "error" in result:
        return jsonify(result), 400
    return jsonify(result)


@app.route('/generate_passphrase', methods=['POST'])
@login_required
@csrf.exempt
def generate_passphrase_route():
    data = request.get_json() or {}
    words = int(data.get('words', 5))
    separator = str(data.get('separator', '-'))
    capitalize = bool(data.get('capitalize', True))
    add_digit = bool(data.get('add_digit', False))
    return jsonify(generate_passphrase(words, separator, capitalize, add_digit))


if __name__ == '__main__':
    init_db()
    port = int(os.environ.get('PORT', '5050'))
    print('\n' + '=' * 64)
    print('  SECUREAUTH HCI ENHANCED VERSION IS RUNNING')
    print(f'  Open: http://127.0.0.1:{port}')
    print('  If localhost:5000 is open, that is your OLD version.')
    print('=' * 64 + '\n')
    app.run(debug=True, port=port)
