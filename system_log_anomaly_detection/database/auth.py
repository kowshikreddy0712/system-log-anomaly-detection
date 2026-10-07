"""User registration, login, and password recovery using SQLite + bcrypt."""

import hashlib
import hmac
import logging
import os
import re
import secrets
import smtplib
import ssl
from email.message import EmailMessage
from pathlib import Path

import bcrypt
from dotenv import load_dotenv

from database.db import get_connection

load_dotenv(Path(__file__).resolve().parents[1] / ".env")

logger = logging.getLogger(__name__)
PASSWORD_RULES = [
    "At least 8 characters",
    "At least one uppercase letter",
    "At least one lowercase letter",
    "At least one number",
    "At least one special character",
]
RESET_CODE_TTL_MINUTES = 15
MAX_RESET_CODE_ATTEMPTS = 5


def _hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def _verify_password(password: str, password_hash: str) -> bool:
    return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))


def password_validation_errors(password: str) -> list[str]:
    errors = []
    if len(password) < 8:
        errors.append("Password must be at least 8 characters long.")
    if not re.search(r"[A-Z]", password):
        errors.append("Password must include at least one uppercase letter.")
    if not re.search(r"[a-z]", password):
        errors.append("Password must include at least one lowercase letter.")
    if not re.search(r"\d", password):
        errors.append("Password must include at least one number.")
    if not re.search(r"[^A-Za-z0-9]", password):
        errors.append("Password must include at least one special character.")
    return errors


def _send_password_reset_email(email: str, code: str) -> None:
    host = os.getenv("SMTP_HOST", "").strip()
    sender = os.getenv("SMTP_FROM_EMAIL", "").strip()
    if not host or not sender:
        raise ValueError("SMTP_HOST and SMTP_FROM_EMAIL must be configured.")

    try:
        port = int(os.getenv("SMTP_PORT", "587"))
    except ValueError as exc:
        raise ValueError("SMTP_PORT must be a valid port number.") from exc
    if not 1 <= port <= 65535:
        raise ValueError("SMTP_PORT must be between 1 and 65535.")

    username = os.getenv("SMTP_USERNAME", "").strip()
    password = os.getenv("SMTP_PASSWORD", "")
    if username and not password:
        raise ValueError("SMTP_PASSWORD is required when SMTP_USERNAME is set.")
    use_tls = os.getenv("SMTP_USE_TLS", "true").strip().lower() in {"1", "true", "yes"}

    message = EmailMessage()
    message["Subject"] = "Linux SOC Monitor password reset"
    message["From"] = sender
    message["To"] = email
    message.set_content(
        f"Your Linux SOC Monitor password reset code is {code}.\n\n"
        f"This code expires in {RESET_CODE_TTL_MINUTES} minutes and can be used once. "
        "If you did not request a password reset, you can ignore this email."
    )

    with smtplib.SMTP(host, port, timeout=10) as server:
        if use_tls:
            server.starttls(context=ssl.create_default_context())
        if username:
            server.login(username, password)
        server.send_message(message)


def request_password_reset(email: str) -> tuple[bool, str]:
    """Email a short-lived code when the address belongs to an account."""
    generic_message = "If an account matches that email, a reset code will be sent."
    conn = get_connection()
    try:
        user = conn.execute(
            "SELECT id, email FROM users WHERE email = ?", (email,)
        ).fetchone()
        if user is None:
            return True, generic_message

        code = f"{secrets.randbelow(1_000_000):06d}"
        code_hash = hashlib.sha256(code.encode("utf-8")).hexdigest()
        conn.execute(
            """
            INSERT INTO password_reset_codes (user_id, code_hash, expires_at, attempts)
            VALUES (?, ?, datetime('now', ?), 0)
            ON CONFLICT(user_id) DO UPDATE SET
                code_hash = excluded.code_hash,
                expires_at = excluded.expires_at,
                attempts = 0,
                created_at = CURRENT_TIMESTAMP
            """,
            (user["id"], code_hash, f"+{RESET_CODE_TTL_MINUTES} minutes"),
        )
        conn.commit()

        try:
            _send_password_reset_email(user["email"], code)
        except (OSError, smtplib.SMTPException, ValueError):
            logger.exception("Could not send password reset email.")
            conn.execute(
                "DELETE FROM password_reset_codes WHERE user_id = ?", (user["id"],)
            )
            conn.commit()
            return False, "The reset email could not be sent. Check the email settings and try again."

        return True, generic_message
    finally:
        conn.close()


def reset_password(email: str, code: str, new_password: str) -> tuple[bool, str]:
    """Change a password with an unexpired emailed code, allowing five attempts."""
    errors = password_validation_errors(new_password)
    if errors:
        return False, " ".join(errors)

    conn = get_connection()
    try:
        reset = conn.execute(
            """
            SELECT users.id, password_reset_codes.code_hash,
                   password_reset_codes.expires_at, password_reset_codes.attempts
            FROM users
            JOIN password_reset_codes ON password_reset_codes.user_id = users.id
            WHERE users.email = ?
            """,
            (email,),
        ).fetchone()
        if reset is None:
            return False, "The reset code is invalid or expired. Request a new code."
        if reset["expires_at"] <= conn.execute("SELECT CURRENT_TIMESTAMP").fetchone()[0]:
            conn.execute(
                "DELETE FROM password_reset_codes WHERE user_id = ?", (reset["id"],)
            )
            conn.commit()
            return False, "The reset code is invalid or expired. Request a new code."
        if reset["attempts"] >= MAX_RESET_CODE_ATTEMPTS:
            return False, "Too many incorrect attempts. Request a new reset code."

        submitted_hash = hashlib.sha256(code.encode("utf-8")).hexdigest()
        if not hmac.compare_digest(submitted_hash, reset["code_hash"]):
            attempts = reset["attempts"] + 1
            if attempts >= MAX_RESET_CODE_ATTEMPTS:
                conn.execute(
                    "DELETE FROM password_reset_codes WHERE user_id = ?", (reset["id"],)
                )
                conn.commit()
                return False, "Too many incorrect attempts. Request a new reset code."
            conn.execute(
                "UPDATE password_reset_codes SET attempts = ? WHERE user_id = ?",
                (attempts, reset["id"]),
            )
            conn.commit()
            return False, "The reset code is invalid or expired."

        conn.execute(
            "UPDATE users SET password_hash = ? WHERE id = ?",
            (_hash_password(new_password), reset["id"]),
        )
        conn.execute(
            "DELETE FROM password_reset_codes WHERE user_id = ?", (reset["id"],)
        )
        conn.commit()
        return True, "Password changed successfully. You can now log in."
    finally:
        conn.close()


def register_user(username: str, email: str, password: str):
    """
    Create a new user account. Returns (success: bool, message: str).
    Passwords are never stored in plaintext.
    """
    conn = get_connection()
    try:
        existing = conn.execute(
            "SELECT id FROM users WHERE username = ? OR email = ?",
            (username, email),
        ).fetchone()
        if existing:
            return False, "Username or email is already registered."

        password_hash = _hash_password(password)
        conn.execute(
            "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
            (username, email, password_hash),
        )
        conn.commit()
        return True, "Account created successfully. You can now log in."
    except Exception as exc:
        return False, f"Registration failed: {exc}"
    finally:
        conn.close()


def authenticate_user(username: str, password: str):
    """
    Verify credentials. Returns (success: bool, user: dict | None, message: str).
    """
    conn = get_connection()
    try:
        user = conn.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()

        if user is None:
            return False, None, "Invalid username or password."
        if not _verify_password(password, user["password_hash"]):
            return False, None, "Invalid username or password."

        return True, dict(user), "Login successful."
    except Exception as exc:
        return False, None, f"Login failed: {exc}"
    finally:
        conn.close()
