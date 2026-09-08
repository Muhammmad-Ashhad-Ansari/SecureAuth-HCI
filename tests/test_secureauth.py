"""
Automated tests for SecureAuth — mirrors the manual test scenarios in the README.
Run with:  pytest -v

Note on timing: several tests below need TOTP codes across more than one
30-second window (e.g. to prove replay prevention, or to log in twice in a
row). Instead of sleeping for real, the `client` fixture patches the app's
time.time() with a controllable fake clock, and tests advance it explicitly
with advance_clock(). This makes replay/lockout tests both correct and fast.
"""
import os
import re
import sys
import time
import pyotp
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import app as secureauth  # noqa: E402


@pytest.fixture()
def client(tmp_path, monkeypatch):
    db_file = tmp_path / "test.db"
    monkeypatch.setattr(secureauth, "DB_PATH", str(db_file))
    secureauth.app.config["TESTING"] = True
    secureauth.init_db()

    clock = {"now": time.time()}
    monkeypatch.setattr(secureauth.time, "time", lambda: clock["now"])

    # Plain client, not `with app.test_client() as c:` — the context-manager form
    # keeps a request context pinned open for the whole test, and if a second
    # client (see test_change_password_invalidates_other_sessions) makes requests
    # while that context is still on the stack, Flask-WTF's CSRF session token
    # gets corrupted ("CSRF session token is missing"). Tests here never need the
    # with-form's only real benefit (inspecting flask.session after a request).
    c = secureauth.app.test_client()
    c.clock = clock
    yield c


def advance_clock(client, seconds):
    client.clock["now"] += seconds


def code_now(totp, client):
    """The TOTP code for the fake clock's current instant, exactly what the
    server-side verifier will also compute for 'now'."""
    return totp.at(client.clock["now"])


def get_csrf(html):
    m = re.search(r'name="csrf_token" value="([^"]+)"', html)
    assert m, "csrf_token not found on page — form is missing its hidden field"
    return m.group(1)


def register_and_enable_2fa(client, username="demo_user", password="Str0ngP@ssw0rd!"):
    r = client.get("/register")
    csrf = get_csrf(r.get_data(as_text=True))
    r = client.post(
        "/register",
        data={
            "csrf_token": csrf,
            "full_name": "Demo User",
            "username": username,
            "password": password,
            "confirm_password": password,
        },
        follow_redirects=True,
    )
    html = r.get_data(as_text=True)
    secret = re.search(r'secret-value">([A-Z2-7]+)<', html).group(1)
    totp = pyotp.TOTP(secret)

    csrf = get_csrf(html)
    r = client.post(
        "/setup-2fa",
        data={"csrf_token": csrf, "otp": code_now(totp, client)},
        follow_redirects=True,
    )
    html = r.get_data(as_text=True)
    codes = re.findall(r'backup-code-chip mono">([A-F0-9]{4}-[A-F0-9]{4})<', html)

    csrf = get_csrf(html)
    client.post("/backup-codes/acknowledge", data={"csrf_token": csrf}, follow_redirects=True)
    return totp, codes


def login_to_otp_screen(client, username="demo_user", password="Str0ngP@ssw0rd!"):
    r = client.get("/login")
    csrf = get_csrf(r.get_data(as_text=True))
    r = client.post(
        "/login",
        data={"csrf_token": csrf, "username": username, "password": password},
        follow_redirects=True,
    )
    return r.get_data(as_text=True)


def full_login(client, totp, username="demo_user", password="Str0ngP@ssw0rd!"):
    """Registers is assumed already done — logs in and clears the OTP screen
    with a fresh, never-used code. Advances the clock past the setup step
    first so the code isn't a replay of the one used during 2FA setup."""
    advance_clock(client, 31)
    html = login_to_otp_screen(client, username, password)
    csrf = get_csrf(html)
    return client.post(
        "/verify-otp",
        data={"csrf_token": csrf, "mode": "totp", "otp": code_now(totp, client)},
        follow_redirects=True,
    )


# ---------------------------------------------------------------------------
# Core flow
# ---------------------------------------------------------------------------

def test_csrf_blocks_requests_without_token(client):
    r = client.post("/login", data={"username": "x", "password": "y"})
    assert r.status_code == 400


def test_direct_dashboard_access_redirects_to_login(client):
    r = client.get("/dashboard")
    assert r.status_code in (301, 302)


def test_full_registration_and_2fa_setup(client):
    totp, codes = register_and_enable_2fa(client)
    assert len(codes) == 10


def test_correct_password_and_correct_otp_grants_access(client):
    totp, _ = register_and_enable_2fa(client)
    r = full_login(client, totp)
    assert "Protected" in r.get_data(as_text=True)


def test_wrong_password_denied(client):
    register_and_enable_2fa(client)
    r = client.get("/login")
    csrf = get_csrf(r.get_data(as_text=True))
    r = client.post("/login", data={"csrf_token": csrf, "username": "demo_user", "password": "wrong"})
    assert "Invalid username or password" in r.get_data(as_text=True)


def test_correct_password_wrong_otp_denied(client):
    register_and_enable_2fa(client)
    html = login_to_otp_screen(client)
    csrf = get_csrf(html)
    r = client.post("/verify-otp", data={"csrf_token": csrf, "mode": "totp", "otp": "111111"})
    assert "Invalid code" in r.get_data(as_text=True)


def test_vault_requires_full_authentication(client):
    r = client.get("/vault")
    assert r.status_code in (301, 302)

    totp, _ = register_and_enable_2fa(client)
    full_login(client, totp)

    r = client.get("/vault")
    assert "Password Security Suite" in r.get_data(as_text=True)


def test_check_strength_is_public(client):
    r = client.post("/check-strength", json={"password": "abc"})
    assert r.status_code == 200
    assert r.get_json()["label"]


def test_passwords_are_never_stored_in_plaintext(client):
    register_and_enable_2fa(client)
    conn = secureauth.get_db()
    row = conn.execute("SELECT password_hash FROM users WHERE username = ?", ("demo_user",)).fetchone()
    conn.close()
    assert row["password_hash"] != "Str0ngP@ssw0rd!"
    assert row["password_hash"].startswith(("pbkdf2:", "scrypt:"))


# ---------------------------------------------------------------------------
# Lockouts
# ---------------------------------------------------------------------------

def test_otp_lockout_after_max_attempts(client):
    register_and_enable_2fa(client)
    html = login_to_otp_screen(client)
    for _ in range(secureauth.MAX_OTP_ATTEMPTS):
        csrf = get_csrf(html)
        r = client.post("/verify-otp", data={"csrf_token": csrf, "mode": "totp", "otp": "111111"})
        html = r.get_data(as_text=True)
    assert "Too many failed attempts" in html


def test_login_lockout_after_max_password_failures(client):
    register_and_enable_2fa(client)
    for _ in range(secureauth.MAX_LOGIN_ATTEMPTS):
        r = client.get("/login")
        csrf = get_csrf(r.get_data(as_text=True))
        r = client.post("/login", data={"csrf_token": csrf, "username": "demo_user", "password": "wrong"})
    assert "Too many failed attempts" in r.get_data(as_text=True)


def test_ip_lockout_across_different_usernames(client):
    """Per-account lockout only protects one username. A source hammering many
    *different* nonexistent usernames from the same IP should still get shut
    down — that's what the separate IP-level counter is for."""
    r = None
    for i in range(secureauth.MAX_IP_ATTEMPTS):
        page = client.get("/login")
        csrf = get_csrf(page.get_data(as_text=True))
        r = client.post(
            "/login",
            data={"csrf_token": csrf, "username": f"nonexistent-{i}", "password": "wrong"},
        )
    assert "Too many failed attempts" in r.get_data(as_text=True)


# ---------------------------------------------------------------------------
# TOTP replay prevention
# ---------------------------------------------------------------------------

def test_totp_replay_is_rejected(client):
    totp, _ = register_and_enable_2fa(client)

    advance_clock(client, 31)
    code = code_now(totp, client)
    html = login_to_otp_screen(client)
    csrf = get_csrf(html)
    r = client.post(
        "/verify-otp",
        data={"csrf_token": csrf, "mode": "totp", "otp": code},
        follow_redirects=True,
    )
    assert "Protected" in r.get_data(as_text=True)

    # same code, same 30-second window, second attempt — must be rejected
    client.get("/logout")
    html = login_to_otp_screen(client)
    csrf = get_csrf(html)
    r = client.post("/verify-otp", data={"csrf_token": csrf, "mode": "totp", "otp": code})
    assert "Invalid code" in r.get_data(as_text=True)


# ---------------------------------------------------------------------------
# Backup codes
# ---------------------------------------------------------------------------

def test_backup_code_login_and_single_use(client):
    totp, codes = register_and_enable_2fa(client)
    code = codes[0]

    html = login_to_otp_screen(client)
    csrf = get_csrf(html)
    r = client.post(
        "/verify-otp",
        data={"csrf_token": csrf, "mode": "backup", "otp": code},
        follow_redirects=True,
    )
    assert "Protected" in r.get_data(as_text=True)

    client.get("/logout")
    html = login_to_otp_screen(client)
    csrf = get_csrf(html)
    r = client.post("/verify-otp", data={"csrf_token": csrf, "mode": "backup", "otp": code})
    assert "Invalid backup code" in r.get_data(as_text=True)


# ---------------------------------------------------------------------------
# 2FA management (settings)
# ---------------------------------------------------------------------------

def test_disable_2fa_requires_password_and_otp(client):
    totp, _ = register_and_enable_2fa(client)
    full_login(client, totp)

    r = client.get("/settings")
    csrf = get_csrf(r.get_data(as_text=True))

    # wrong password + right-looking otp — must be rejected, 2FA stays on
    r = client.post(
        "/settings/disable-2fa",
        data={"csrf_token": csrf, "current_password": "wrongpass", "otp": "111111"},
    )
    assert "Incorrect password or authentication code" in r.get_data(as_text=True)

    # correct password + valid, unused OTP — succeeds
    advance_clock(client, 31)
    code = code_now(totp, client)
    r = client.get("/settings")
    csrf = get_csrf(r.get_data(as_text=True))
    r = client.post(
        "/settings/disable-2fa",
        data={"csrf_token": csrf, "current_password": "Str0ngP@ssw0rd!", "otp": code},
        follow_redirects=True,
    )
    assert "Incorrect password or authentication code" not in r.get_data(as_text=True)

    conn = secureauth.get_db()
    row = conn.execute("SELECT two_factor_enabled FROM users WHERE username = ?", ("demo_user",)).fetchone()
    conn.close()
    assert row["two_factor_enabled"] == 0


def test_login_skips_otp_when_2fa_disabled(client):
    totp, _ = register_and_enable_2fa(client)
    full_login(client, totp)

    advance_clock(client, 31)
    code = code_now(totp, client)
    r = client.get("/settings")
    csrf = get_csrf(r.get_data(as_text=True))
    client.post(
        "/settings/disable-2fa",
        data={"csrf_token": csrf, "current_password": "Str0ngP@ssw0rd!", "otp": code},
    )

    client.get("/logout")
    r = client.get("/login")
    csrf = get_csrf(r.get_data(as_text=True))
    r = client.post(
        "/login",
        data={"csrf_token": csrf, "username": "demo_user", "password": "Str0ngP@ssw0rd!"},
        follow_redirects=True,
    )
    # straight to the dashboard, no OTP screen in between
    assert "Protected" in r.get_data(as_text=True)


def test_2fa_enabled_still_requires_otp(client):
    """Regression guard: a 2FA-enabled account must never fall through to a
    password-only login just because the disabled-2FA path now exists."""
    totp, _ = register_and_enable_2fa(client)
    html = login_to_otp_screen(client)
    assert "Enter verification code" in html


# ---------------------------------------------------------------------------
# Session security
# ---------------------------------------------------------------------------

def test_change_password_invalidates_other_sessions(client):
    totp, _ = register_and_enable_2fa(client)
    full_login(client, totp)

    # a second "device" logging in as the same user, sharing the same test DB
    client2 = secureauth.app.test_client()
    client2.clock = client.clock
    advance_clock(client, 31)
    html = login_to_otp_screen(client2)
    csrf = get_csrf(html)
    client2.post(
        "/verify-otp",
        data={"csrf_token": csrf, "mode": "totp", "otp": code_now(totp, client2)},
        follow_redirects=True,
    )
    assert "Protected" in client2.get("/dashboard").get_data(as_text=True)

    # client1 changes the password
    r = client.get("/settings")
    csrf = get_csrf(r.get_data(as_text=True))
    client.post(
        "/settings/change-password",
        data={
            "csrf_token": csrf,
            "current_password": "Str0ngP@ssw0rd!",
            "new_password": "EvenStr0nger!!",
            "confirm_new_password": "EvenStr0nger!!",
        },
    )

    # client1 (who made the change) stays logged in
    assert client.get("/dashboard").status_code == 200
    # client2's older session is now revoked
    r2 = client2.get("/dashboard")
    assert r2.status_code in (301, 302)
