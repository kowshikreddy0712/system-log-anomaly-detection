"""Login and registration screen, shown when nobody is logged in."""

import streamlit as st

from database.auth import (
    PASSWORD_RULES,
    authenticate_user,
    password_validation_errors,
    register_user,
    request_password_reset,
    reset_password,
)

def render() -> None:
    st.markdown('<div class="auth-wrapper">', unsafe_allow_html=True)
    col1, col2, col3 = st.columns([1, 1.3, 1])

    with col2:
        st.markdown(
            """
            <div class="auth-header">
                <div class="brand-mark">🛡</div>
                <h1>Linux SOC Monitor</h1>
                <p>Linux System Log Anomaly Detection &amp; Security Analytics</p>
            </div>
            """,
            unsafe_allow_html=True,
        )

        st.markdown('<div class="auth-card">', unsafe_allow_html=True)
        tab_login, tab_register = st.tabs(["Login", "Create Account"])
        with tab_login:
            _render_login_form()
        with tab_register:
            _render_register_form()
        st.markdown('</div>', unsafe_allow_html=True)

    st.markdown('</div>', unsafe_allow_html=True)


def _render_login_form() -> None:
    if st.session_state.pop("password_reset_notice", None):
        st.success("Password changed successfully. You can now log in.")

    if st.session_state.get("show_password_reset"):
        _render_password_reset_form()
        return

    with st.form("login_form"):
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        submitted = st.form_submit_button("Login", use_container_width=True, type="primary")

        if submitted:
            if not username or not password:
                st.error("Please enter both username and password.")
                return

            success, user, message = authenticate_user(username, password)
            if success:
                st.session_state.logged_in = True
                st.session_state.username = user["username"]
                st.session_state.user_id = user["id"]
                st.success(message)
                st.rerun()
            else:
                st.error(message)

    if st.button("Forgot password?", key="forgot_password"):
        st.session_state.show_password_reset = True
        st.rerun()


def _render_password_reset_form() -> None:
    st.markdown("### Reset your password")
    email = st.session_state.get("password_reset_email")

    if email is None:
        with st.form("request_password_reset_form"):
            reset_email = st.text_input("Registered email address")
            submitted = st.form_submit_button(
                "Send reset code", use_container_width=True, type="primary"
            )
        if submitted:
            if not reset_email or "@" not in reset_email:
                st.error("Enter the email address associated with your account.")
            else:
                success, message = request_password_reset(reset_email.strip())
                if success:
                    st.session_state.password_reset_email = reset_email.strip()
                    st.info(message)
                    st.rerun()
                else:
                    st.error(message)
    else:
        st.info(
            "If an account matches that email, a reset code was sent. "
            "The code expires in 15 minutes."
        )
        with st.form("complete_password_reset_form"):
            code = st.text_input("Reset code", max_chars=6)
            password = st.text_input("New password", type="password")
            confirm_password = st.text_input("Confirm new password", type="password")
            st.caption("Password rules:")
            for rule in PASSWORD_RULES:
                st.caption(f"• {rule}")
            submitted = st.form_submit_button(
                "Change password", use_container_width=True, type="primary"
            )

        if submitted:
            errors = password_validation_errors(password)
            if not code or not code.isdigit() or len(code) != 6:
                errors.insert(0, "Enter the 6-digit reset code.")
            if password != confirm_password:
                errors.append("Passwords do not match.")
            if errors:
                for error in errors:
                    st.error(error)
            else:
                success, message = reset_password(email, code, password)
                if success:
                    st.session_state.pop("password_reset_email", None)
                    st.session_state.pop("show_password_reset", None)
                    st.session_state.password_reset_notice = True
                    st.rerun()
                else:
                    st.error(message)

    if st.button("Back to login", key="back_to_login"):
        st.session_state.pop("password_reset_email", None)
        st.session_state.pop("show_password_reset", None)
        st.rerun()


def _render_register_form() -> None:
    with st.form("register_form"):
        username = st.text_input("Choose a username", key="reg_username")
        email = st.text_input("Email", key="reg_email")
        password = st.text_input("Password", type="password", key="reg_password")
        confirm_password = st.text_input("Confirm password", type="password", key="reg_confirm")
        st.caption("Password rules:")
        for rule in PASSWORD_RULES:
            st.caption(f"• {rule}")
        submitted = st.form_submit_button("Create Account", use_container_width=True, type="primary")

        if submitted:
            errors = _validate_registration(username, email, password, confirm_password)
            if errors:
                for error in errors:
                    st.error(error)
                return

            success, message = register_user(username, email, password)
            if success:
                st.success(message)
            else:
                st.error(message)


def _validate_registration(username: str, email: str, password: str, confirm_password: str) -> list:
    errors = []
    if not username or len(username) < 3:
        errors.append("Username must be at least 3 characters.")
    if not email or "@" not in email or "." not in email.split("@")[-1]:
        errors.append("Please enter a valid email address.")
    errors.extend(password_validation_errors(password))
    if password != confirm_password:
        errors.append("Passwords do not match.")
    return errors
