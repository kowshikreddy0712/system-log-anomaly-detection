"""Tests for account authentication and password recovery."""

import os
import smtplib
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import database.auth as auth
from database.db import init_db


@pytest.fixture
def auth_database(tmp_path, monkeypatch):
    import database.db as db

    monkeypatch.setattr(db, "DB_PATH", tmp_path / "test_auth.db")
    init_db()
    auth.register_user("analyst", "analyst@example.com", "SecurePass1!")
    return db.DB_PATH


def test_email_reset_changes_password_and_invalidates_code(
    auth_database, monkeypatch
):
    sent = {}

    def capture_email(email, code):
        sent["email"] = email
        sent["code"] = code

    monkeypatch.setattr(auth, "_send_password_reset_email", capture_email)
    success, message = auth.request_password_reset("analyst@example.com")

    assert success
    assert "If an account matches" in message
    assert sent["email"] == "analyst@example.com"

    success, message = auth.reset_password(
        "analyst@example.com", sent["code"], "ChangedPass2!"
    )

    assert success
    assert auth.authenticate_user("analyst", "ChangedPass2!")[0]
    assert not auth.authenticate_user("analyst", "SecurePass1!")[0]
    assert not auth.reset_password(
        "analyst@example.com", sent["code"], "AnotherPass3!"
    )[0]


def test_reset_code_is_invalidated_after_five_incorrect_attempts(
    auth_database, monkeypatch
):
    sent = {}
    monkeypatch.setattr(
        auth, "_send_password_reset_email", lambda _email, code: sent.update(code=code)
    )
    auth.request_password_reset("analyst@example.com")
    wrong_code = "000000" if sent["code"] != "000000" else "000001"

    last_message = ""
    for _ in range(auth.MAX_RESET_CODE_ATTEMPTS):
        success, last_message = auth.reset_password(
            "analyst@example.com", wrong_code, "ChangedPass2!"
        )
        assert not success
    assert "Too many incorrect attempts" in last_message

    success, message = auth.reset_password(
        "analyst@example.com", wrong_code, "ChangedPass2!"
    )
    assert not success
    assert "invalid or expired" in message


def test_reset_code_expiration_is_enforced(auth_database, monkeypatch):
    monkeypatch.setattr(auth, "_send_password_reset_email", lambda _email, _code: None)
    auth.request_password_reset("analyst@example.com")

    conn = auth.get_connection()
    try:
        conn.execute(
            "UPDATE password_reset_codes SET expires_at = '2000-01-01 00:00:00'"
        )
        conn.commit()
    finally:
        conn.close()

    success, message = auth.reset_password(
        "analyst@example.com", "123456", "ChangedPass2!"
    )
    assert not success
    assert "invalid or expired" in message


def test_password_reset_requires_existing_email(auth_database, monkeypatch):
    def fail_if_sent(_email, _code):
        pytest.fail("No email should be sent for an unknown address.")

    monkeypatch.setattr(auth, "_send_password_reset_email", fail_if_sent)
    success, message = auth.request_password_reset("unknown@example.com")
    assert success
    assert "If an account matches" in message


def test_reset_rejects_password_that_does_not_meet_rules(auth_database, monkeypatch):
    monkeypatch.setattr(auth, "_send_password_reset_email", lambda _email, _code: None)
    auth.request_password_reset("analyst@example.com")

    success, message = auth.reset_password(
        "analyst@example.com", "123456", "weak"
    )
    assert not success
    assert "at least 8 characters" in message


def test_failed_email_delivery_does_not_leave_a_usable_code(
    auth_database, monkeypatch
):
    def fail_to_send(_email, _code):
        raise smtplib.SMTPException("delivery failed")

    monkeypatch.setattr(auth, "_send_password_reset_email", fail_to_send)
    success, message = auth.request_password_reset("analyst@example.com")

    assert not success
    assert "could not be sent" in message
    conn = auth.get_connection()
    try:
        assert conn.execute(
            "SELECT COUNT(*) FROM password_reset_codes"
        ).fetchone()[0] == 0
    finally:
        conn.close()
