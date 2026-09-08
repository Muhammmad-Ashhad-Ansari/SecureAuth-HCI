## HCI Enhanced v3 — modal visibility fix

This build fixes the native `[hidden]` state for help dialogs, accessibility panels, toasts, filtered timeline items, and OTP warnings.

# IMPORTANT — Run the HCI Enhanced Build

This enhanced build intentionally runs on **http://127.0.0.1:5050** so it cannot be confused with an older SecureAuth process on port 5000. On Windows, double-click **RUN_ENHANCED.bat** after dependencies are installed. If dependencies are missing, use **INSTALL_AND_RUN_ENHANCED.bat** once.

If you still see the old UI, close old terminals running Flask and open port **5050**, not 5000.

---

# SecureAuth — TOTP-Based Two-Factor Authentication System

A university Information Security Lab project. Combines a working 2FA authentication
system with a bundled **Password Security Suite** (strength analyzer, secure password
generator, and passphrase generator) that sits behind the login as the protected resource.

## Overview

Two independent factors are required to reach the protected area:

1. **Something you know** — username + password (hashed, never stored in plain text)
2. **Something you have** — a 6-digit Time-based One-Time Password (TOTP) from an
   authenticator app (Google Authenticator, Microsoft Authenticator, etc.)

The dashboard and the Password Security Suite are only reachable once both factors
are verified in the same session.

## Features

- Registration with hashed passwords (Werkzeug `generate_password_hash`)
- Per-user TOTP secret, QR code enrollment (`otpauth://` URI via `pyotp` + `qrcode`)
- Two-stage login: password check → pre-auth session → OTP check → full session
- **CSRF protection** on every state-changing form (Flask-WTF)
- **Account lockout** after 5 failed OTP attempts *and* separately after 5 failed
  password attempts (60-second cooldown each, tracked independently)
- **10 single-use backup codes** issued at 2FA setup — recover access if the phone
  with the authenticator app is lost; can be regenerated anytime from the dashboard
- **15-minute idle session timeout** — the signed session cookie expires automatically
- **Persistent secret key** stored in `.env` (auto-generated on first run) — sessions
  now survive server restarts instead of invalidating every time
- **Live password strength meter** on the registration form (calls `/check-strength`
  as you type, debounced, using the same scoring engine as the analyzer)
- **30-second OTP countdown ring** on the verification screen
- **IP-based rate limiting**, separate from per-account lockout — stops one source
  from spraying guesses across many different usernames
- **TOTP replay prevention** — the last successfully-used time-step is tracked per
  user, so a captured/reused valid code is rejected even while still "current"
- **Security settings page**: change password, disable/re-enable 2FA, regenerate
  backup codes, log out all other sessions
- **Session security** — a `session_version` per user invalidates every other active
  session the moment the password changes or "log out other sessions" is used
- Full activity log (successful/failed password, OTP, and backup-code attempts, logout)
- Password Security Suite as the protected "vault": entropy-based strength analyzer,
  cryptographically secure password generator (`secrets` module), passphrase generator
- Direct URL access to `/dashboard` or `/vault` without authentication redirects to login
- Automated `pytest` suite covering all 18 security scenarios (see Testing below)

## HCI & Visible Usability Enhancements

The interface is designed as a visible **Security Control Center**, not only a code-entry demo. The current build includes:

- Security score with a clear protection state and recommended attention areas
- Guided sign-in stepper: Password → Verification → Access
- Guided 2FA setup journey: Account → Scan → Verify → Recovery
- "Why you're protected" explanation of the two independent authentication factors
- Real browser/device/IP context on the verification and current-session screens (no guessed location data)
- OTP countdown with an expiry warning to reduce mistimed-code errors
- Recovery Center with remaining backup-code visibility and regeneration controls
- Copy-all / print recovery-code actions plus explicit save confirmation
- Filterable authentication activity timeline with successful, failed, and security-change views
- Current verified-session card and one-click sign-out of other sessions
- Context-sensitive help dialogs instead of a long separate help manual
- Accessibility preferences for larger text, high contrast, reduced motion, plus light/dark theme
- Live password-strength feedback, visible password requirements, and password-match feedback during registration
- Responsive authenticated workspace optimized for desktop and mobile screens

These visible improvements support HCI goals including visibility of system status, immediate feedback, error prevention and recovery, recognition over recall, user control, consistency, accessibility, and minimalist progressive disclosure.

## Technology Stack

- **Backend:** Python, Flask, Flask-WTF (CSRF), python-dotenv
- **Frontend:** HTML5, CSS3, vanilla JavaScript
- **Database:** SQLite (via `sqlite3`, parameterized queries)
- **Security:** PyOTP (TOTP), `qrcode` (QR generation), Werkzeug (password hashing)

No paid services, no internet dependency after install, no React/Docker/cloud.

## Installation

```bash
cd SecureAuth
pip install -r requirements.txt
cp .env.example .env   # optional — a key is auto-generated into .env on first run anyway
```

## Running the Project

```bash
python app.py
```

Then open:

```
http://127.0.0.1:5000
```

The SQLite database (`database.db`) and both tables (`users`, `activity_log`) are
created automatically on first run.

## How to Register

1. Open the landing page → **Get Started**
2. Fill in Full Name, Username, Password, Confirm Password → **Register**
3. You're taken straight to 2FA setup — registration alone does not grant access.
4. After enabling 2FA you'll see 10 backup codes once — save them, then continue to login.

## How to Configure the Authenticator App

1. On the setup screen, open Google Authenticator / Microsoft Authenticator
2. Tap **Add account** → **Scan a QR code**
3. Scan the QR code shown (or type in the manual entry key below it)
4. Enter the 6-digit code currently displayed in the app → **Verify & Enable 2FA**

## How to Test OTP

- After 2FA is enabled, log in with your username and password
- You'll be sent to the OTP verification screen
- Enter the current 6-digit code from your authenticator app
- Codes rotate every 30 seconds — if it doesn't work, wait for the next one

## Security Features

- Passwords hashed with Werkzeug (PBKDF2), never stored or shown in plain text
- Generic "Invalid username or password" error — doesn't reveal which one was wrong
- Full authenticated session only created after **both** factors pass
- Session cleared on logout
- Parameterized SQL everywhere — no string concatenation of user input
- Failed-OTP lockout: 5 attempts → 60-second cooldown

## Testing Scenarios

| # | Scenario | Expected Result |
|---|----------|------------------|
| 1 | Correct password + correct OTP | Access Granted → Dashboard |
| 2 | Wrong password | Access Denied |
| 3 | Correct password + wrong OTP | Access Denied |
| 4 | Expired/invalid OTP | Access Denied |
| 5 | 5 repeated failed OTP attempts | Temporary lockout (60s) |
| 6 | Direct `/dashboard` or `/vault` access, no session | Redirect to Login |
| 7 | 5 repeated failed password attempts | Temporary lockout (60s), tracked separately from OTP |
| 8 | Login via backup code instead of OTP | Access Granted, code marked used |
| 9 | Re-using an already-used backup code | Access Denied |
| 10 | POST to any form without a CSRF token | 400 Bad Request |
| 11 | 15 failed attempts across different usernames, same IP | IP-level lockout (120s) |
| 12 | Reusing a valid, already-accepted TOTP code | Access Denied (replay rejected) |
| 13 | Disabling 2FA with wrong password/OTP | Rejected, 2FA stays enabled |
| 14 | Login after 2FA is disabled | Password alone reaches the dashboard, no OTP screen |
| 15 | Login while 2FA is still enabled | OTP screen still required (regression check) |
| 16 | Changing password from one session | Every other active session is signed out |

All sixteen are automated in `tests/test_secureauth.py`, alongside a few extra
sanity checks (password hashing, public strength-check endpoint) — 18 tests total.
Run them with:

```bash
pytest -v
```

## Demo Flow (5–10 min)

1. Open SecureAuth landing page
2. Register a new account
3. Scan QR with authenticator app, enable 2FA
4. Log in with username/password
5. Enter correct OTP → land on Dashboard
6. Open the Password Security Suite from the dashboard, try the analyzer/generator
7. Logout
8. Try wrong password → Access Denied
9. Log in correctly, try wrong OTP → Access Denied
10. Try visiting `/dashboard` directly in a new tab without logging in → redirected to Login

## Project Limitations

- No password reset flow if the account password itself is forgotten
- IP-based rate limiting uses `request.remote_addr`, so it's blind to attackers
  behind a shared NAT/proxy or a large botnet spreading requests across many IPs
- SQLite is fine for a lab demo, not for concurrent production load
- No HTTPS enforced (fine for `127.0.0.1` local demo, required for production)
- TOTP secrets are stored as plain text in SQLite (see the comment in `app.py`
  above where they're saved) — acceptable for a lab project, not for production

## Future Improvements

- Encrypt TOTP secrets at rest
- Move to PostgreSQL and add HTTPS for a real deployment
- Add a "trust this device for 30 days" option
- Email-based password reset flow

---

## Viva Questions & Answers

**1. What is authentication?**
Confirming that a user is who they claim to be before granting access.

**2. What is 2FA?**
Two-Factor Authentication — requiring two different types of proof of identity instead
of just one, e.g. a password plus a code from a device.

**3. What is TOTP?**
Time-based One-Time Password — a 6-digit code generated from a shared secret and the
current time, valid for a short window (usually 30 seconds).

**4. Difference between OTP and TOTP?**
OTP is any one-time code (could be sent by SMS, email, etc.). TOTP specifically derives
the code from a secret key and the current timestamp, so no network delivery is needed.

**5. Why use an authenticator app instead of SMS?**
No carrier dependency, no SIM-swap risk, works offline, and it's free.

**6. What is a TOTP secret?**
A random key generated for each user at setup time. It's shared once (via QR code)
between the server and the authenticator app, then never transmitted again.

**7. Why is a QR code used?**
It encodes the `otpauth://` URI (secret, account name, issuer) so the user doesn't
have to type a long random string by hand.

**8. How does the authenticator app generate the code?**
It runs the same TOTP algorithm as the server: `HMAC(secret, current_time_step)`,
truncated to 6 digits. Same secret + same time = same code on both sides.

**9. Why does the OTP expire?**
So a leaked or intercepted code can't be reused later — it's only valid for the
current 30-second time step (plus a small tolerance window).

**10. What happens if the password is correct but OTP is wrong?**
Access is denied. A temporary pre-auth session exists after the password check, but
no full session is created until the OTP also passes.

**11. Why hash passwords?**
So that even if the database is stolen, the actual passwords aren't exposed — only
irreversible hashes are stored.

**12. What is password hashing?**
A one-way function that turns a password into a fixed-length string. It can be
verified (by hashing the input again and comparing) but never reversed back to
the original password.

**13. Why SQLite?**
Zero-configuration, file-based, ships with Python — ideal for a local lab project
with no server setup required.

**14. What is session authentication?**
After login, the server stores an identifier in a cookie (`session`). Each request
after that carries the cookie, so the server knows who's asking without re-checking
credentials every time.

**15. What is brute force?**
Repeatedly guessing passwords or OTPs until one works, usually via automated tools.

**16. How does account lockout help?**
It caps the number of guesses an attacker can make in a given time, making brute
force impractical.

**17. What is the purpose of the security dashboard?**
To give the user visibility into their account's security status and recent
authentication activity after they've proven their identity.

**18. What security vulnerabilities does this project address?**
Weak/reused passwords (via hashing + the strength analyzer), credential-only login
(via 2FA), and brute-force guessing (via lockout).

**19. What are the limitations of this implementation?**
No password recovery flow (only a change-password option for logged-in users),
IP-based rate limiting can't see past a shared NAT, SQLite isn't built for
concurrent production traffic, and TOTP secrets aren't encrypted at rest.

**20. How could this system be improved in production?**
Add HTTPS, move to a production database, encrypt TOTP secrets at rest, and add
proxy-aware IP detection so rate limiting works correctly behind a load balancer.

**21. What is CSRF and how does this project prevent it?**
Cross-Site Request Forgery — tricking a logged-in user's browser into submitting
a request they didn't intend to. Flask-WTF issues a unique token per session and
rejects any POST that doesn't include it, so a forged form on another site can't
submit valid requests on the user's behalf.

**22. What happens if a user loses their phone with the authenticator app?**
They use one of the 10 backup codes issued at 2FA setup instead of a TOTP code.
Each backup code works exactly once and is stored as a hash, just like the password.

**23. Why lock the account after failed attempts on both password AND OTP?**
Each factor is a separate attack surface. Locking only OTP attempts would still
let an attacker brute-force the password indefinitely; both need their own limit.

**24. What is TOTP replay prevention, and why is time-window tolerance not enough?**
`valid_window=1` only makes the server tolerant of small clock drift between the
server and the user's phone — it does nothing to stop the *same* correct code
being submitted twice in a row. This project tracks the last time-step each user
successfully used and rejects that step (or any earlier one) on a second attempt,
so a code intercepted in transit can't be replayed even while it's still "current."

**25. What's the difference between the account lockout and the IP lockout?**
Account lockout (5 failed attempts) protects one specific username from being
brute-forced. IP lockout (15 failed attempts) protects against a single source
spraying guesses across *many different* usernames, which the account-level
counter alone wouldn't catch since no single account would hit its own threshold.

**26. Why does disabling 2FA require both the current password AND a TOTP code?**
A stolen, already-logged-in browser session shouldn't be enough on its own to
strip an account of its second factor. Requiring both proves the person turning
2FA off still controls the same two things an attacker would need to log in in
the first place.

**27. What does "log out other sessions" actually do?**
Every user has a `session_version` counter in the database. Each login stamps
that version into the session cookie. Logging out other sessions (or changing
the password) increments the counter — any other session cookie is now carrying
a stale version, so the very next request from that browser gets redirected to
login, even though its cookie is still cryptographically valid.
