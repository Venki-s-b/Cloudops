"""
CloudOps Central — Email Service (SMTP)
Handles: welcome emails, password reset OTPs, alert notifications.
"""

import asyncio
import logging
import secrets
import sqlite3
import json
import os
from datetime import datetime, timedelta, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

log = logging.getLogger("cloudops.email")

DB_PATH = os.path.join(os.path.dirname(__file__), "cloudops.db")


def _db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_email_tables():
    with _db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS smtp_config (
                id      INTEGER PRIMARY KEY CHECK (id = 1),
                data    TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS otp_tokens (
                token      TEXT PRIMARY KEY,
                username   TEXT NOT NULL,
                purpose    TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                used       INTEGER DEFAULT 0
            )
        """)
        conn.commit()


init_email_tables()


# ─── SMTP CONFIG CRUD ─────────────────────────────────────────────────────────

def get_smtp_config() -> dict | None:
    with _db() as conn:
        row = conn.execute("SELECT data FROM smtp_config WHERE id=1").fetchone()
    return json.loads(row["data"]) if row else None


def save_smtp_config(cfg: dict):
    with _db() as conn:
        conn.execute(
            "INSERT INTO smtp_config (id, data) VALUES (1, ?) "
            "ON CONFLICT(id) DO UPDATE SET data=excluded.data",
            (json.dumps(cfg),)
        )
        conn.commit()


# ─── OTP HELPERS ──────────────────────────────────────────────────────────────

def create_otp(username: str, purpose: str, ttl_minutes: int = 30) -> str:
    token = secrets.token_urlsafe(32)
    expires = (datetime.now(timezone.utc) + timedelta(minutes=ttl_minutes)).isoformat()
    with _db() as conn:
        # Invalidate old tokens for same user+purpose
        conn.execute(
            "DELETE FROM otp_tokens WHERE username=? AND purpose=?",
            (username, purpose)
        )
        conn.execute(
            "INSERT INTO otp_tokens (token, username, purpose, expires_at) VALUES (?,?,?,?)",
            (token, username, purpose, expires)
        )
        conn.commit()
    return token


def verify_otp(token: str, purpose: str) -> str | None:
    """Returns username if valid, None otherwise. Marks token as used."""
    with _db() as conn:
        row = conn.execute(
            "SELECT username, expires_at, used FROM otp_tokens WHERE token=? AND purpose=?",
            (token, purpose)
        ).fetchone()
        if not row or row["used"]:
            return None
        if datetime.fromisoformat(row["expires_at"]) < datetime.now(timezone.utc):
            return None
        conn.execute("UPDATE otp_tokens SET used=1 WHERE token=?", (token,))
        conn.commit()
        return row["username"]


# ─── EMAIL SENDER ─────────────────────────────────────────────────────────────

async def send_email(to: str, subject: str, html_body: str) -> bool:
    cfg = get_smtp_config()
    if not cfg or not cfg.get("enabled"):
        log.warning("SMTP not configured or disabled — skipping email to %s", to)
        return False

    try:
        import aiosmtplib

        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = f"{cfg.get('from_name', 'CloudOps Central')} <{cfg['from_email']}>"
        msg["To"] = to
        msg.attach(MIMEText(html_body, "html"))

        await aiosmtplib.send(
            msg,
            hostname=cfg["host"],
            port=int(cfg.get("port", 587)),
            username=cfg.get("username"),
            password=cfg.get("password"),
            use_tls=cfg.get("use_tls", False),
            start_tls=cfg.get("start_tls", True),
        )
        log.info("Email sent to %s: %s", to, subject)
        return True
    except Exception as e:
        log.error("Failed to send email to %s: %s", to, e)
        return False


# ─── EMAIL TEMPLATES ──────────────────────────────────────────────────────────

def _base_template(content: str) -> str:
    return f"""
<!DOCTYPE html><html><body style="margin:0;padding:0;background:#0d1117;font-family:'Segoe UI',sans-serif;">
<table width="100%" cellpadding="0" cellspacing="0">
  <tr><td align="center" style="padding:40px 20px;">
    <table width="520" cellpadding="0" cellspacing="0" style="background:#111827;border:1px solid #1e3a52;border-radius:16px;overflow:hidden;">
      <tr><td style="background:linear-gradient(90deg,#0a1f33,#0d2a1a);padding:24px 32px;border-bottom:1px solid #1e3a52;">
        <span style="font-size:20px;font-weight:700;color:#10d97a;letter-spacing:0.05em;">⬡ CloudOps Central</span>
      </td></tr>
      <tr><td style="padding:32px;">{content}</td></tr>
      <tr><td style="padding:16px 32px;border-top:1px solid #1e3a52;text-align:center;">
        <span style="font-size:11px;color:#4d7a9e;">This is an automated message from CloudOps Central. Do not reply.</span>
      </td></tr>
    </table>
  </td></tr>
</table>
</body></html>"""


async def send_welcome_email(to: str, name: str, username: str, temp_password: str):
    content = f"""
<p style="color:#e2eaf4;font-size:16px;margin:0 0 16px;">Welcome, <strong style="color:#10d97a;">{name}</strong>!</p>
<p style="color:#9ab2c8;font-size:14px;line-height:1.6;margin:0 0 24px;">
  Your CloudOps Central account has been created. Use the credentials below to sign in.
</p>
<table style="background:#0d1117;border:1px solid #1e3a52;border-radius:10px;padding:20px;width:100%;margin-bottom:24px;">
  <tr><td style="color:#4d7a9e;font-size:12px;font-family:monospace;padding:4px 0;">USERNAME</td>
      <td style="color:#10d97a;font-size:14px;font-family:monospace;font-weight:700;">{username}</td></tr>
  <tr><td style="color:#4d7a9e;font-size:12px;font-family:monospace;padding:4px 0;">PASSWORD</td>
      <td style="color:#f0c040;font-size:14px;font-family:monospace;font-weight:700;">{temp_password}</td></tr>
</table>
<p style="color:#f05050;font-size:12px;">⚠ Please change your password immediately after first login.</p>"""
    await send_email(to, "Welcome to CloudOps Central — Your Account Details", _base_template(content))


async def send_password_reset_email(to: str, name: str, reset_link: str):
    content = f"""
<p style="color:#e2eaf4;font-size:16px;margin:0 0 16px;">Hi <strong style="color:#10d97a;">{name}</strong>,</p>
<p style="color:#9ab2c8;font-size:14px;line-height:1.6;margin:0 0 24px;">
  A password reset was requested for your account. Click the button below to reset your password.
  This link expires in <strong style="color:#f0c040;">30 minutes</strong>.
</p>
<div style="text-align:center;margin:24px 0;">
  <a href="{reset_link}" style="background:linear-gradient(135deg,#0d9a58,#10d97a);color:#050f0a;padding:14px 32px;border-radius:10px;text-decoration:none;font-weight:700;font-size:14px;display:inline-block;">
    Reset Password
  </a>
</div>
<p style="color:#4d7a9e;font-size:12px;">If you did not request this, ignore this email. Your password will not change.</p>"""
    await send_email(to, "CloudOps Central — Password Reset Request", _base_template(content))


async def send_alert_notification(to: str, account_name: str, alerts: list):
    rows = "".join(
        f'<tr><td style="color:#e2eaf4;padding:8px;font-size:13px;">{a.get("name","—")}</td>'
        f'<td style="color:#f05050;padding:8px;font-size:13px;">{a.get("sev","—").upper()}</td>'
        f'<td style="color:#9ab2c8;padding:8px;font-size:13px;">{a.get("metric","—")}</td></tr>'
        for a in alerts[:10]
    )
    content = f"""
<p style="color:#f05050;font-size:16px;font-weight:700;margin:0 0 16px;">🚨 Active Alerts — {account_name}</p>
<table style="width:100%;border-collapse:collapse;margin-bottom:16px;">
  <tr style="border-bottom:1px solid #1e3a52;">
    <th style="color:#4d7a9e;font-size:11px;text-align:left;padding:8px;">ALARM</th>
    <th style="color:#4d7a9e;font-size:11px;text-align:left;padding:8px;">SEVERITY</th>
    <th style="color:#4d7a9e;font-size:11px;text-align:left;padding:8px;">METRIC</th>
  </tr>
  {rows}
</table>
<p style="color:#9ab2c8;font-size:12px;">Log in to CloudOps Central to investigate and resolve these alerts.</p>"""
    await send_email(to, f"[CloudOps Alert] {len(alerts)} active alarm(s) in {account_name}", _base_template(content))
