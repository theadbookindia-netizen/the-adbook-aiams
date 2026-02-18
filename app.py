import os
import re
import hmac
import json
import time
import base64
import hashlib
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple, List

import streamlit as st
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine


# =========================================================
# CONFIG / SECRETS
# =========================================================

def get_secret(name: str, default: Optional[str] = None) -> Optional[str]:
    # Prefer Streamlit secrets, fallback to env
    if name in st.secrets:
        return str(st.secrets[name])
    return os.getenv(name, default)


def normalize_database_url(raw_url: str) -> str:
    """
    Ensures SQLAlchemy uses psycopg3 driver.

    Accepts:
      postgresql://...
      postgres://...  (some people use this)
      postgresql+psycopg://...

    Returns:
      postgresql+psycopg://...
    """
    url = raw_url.strip()

    # Common alias
    if url.startswith("postgres://"):
        url = "postgresql://" + url[len("postgres://"):]

    # Force psycopg3 dialect for SQLAlchemy
    if url.startswith("postgresql://"):
        url = "postgresql+psycopg://" + url[len("postgresql://"):]

    return url


# =========================================================
# DATABASE ENGINE
# =========================================================

@st.cache_resource(show_spinner=False)
def db_engine() -> Engine:
    raw = get_secret("DATABASE_URL")
    if not raw:
        st.error("DATABASE_URL is missing. Add it in Streamlit Secrets.")
        st.stop()

    db_url = normalize_database_url(raw)

    # CRITICAL for Supabase pooler / PgBouncer:
    # psycopg3 prepared statements can break in transaction pooling
    connect_args = {
        "prepare_threshold": None,  # disables prepared statements
        "sslmode": "require",
    }

    # Reasonable pooling defaults for Streamlit
    return create_engine(
        db_url,
        pool_pre_ping=True,
        pool_recycle=300,
        future=True,
        connect_args=connect_args,
    )


def exec_sql(sql: str, params: Optional[Dict[str, Any]] = None) -> None:
    with db_engine().begin() as conn:
        conn.execute(text(sql), params or {})


def fetch_one(sql: str, params: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, Any]]:
    with db_engine().connect() as conn:
        row = conn.execute(text(sql), params or {}).mappings().first()
        return dict(row) if row else None


def fetch_all(sql: str, params: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    with db_engine().connect() as conn:
        rows = conn.execute(text(sql), params or {}).mappings().all()
        return [dict(r) for r in rows]


# =========================================================
# PASSWORD HASHING (PBKDF2)
# =========================================================

def pbkdf2_hash(password: str, salt: str, rounds: int = 200_000) -> str:
    """
    Returns: pbkdf2_sha256$SALT$HEXHASH
    """
    dk = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        rounds,
    )
    return f"pbkdf2_sha256${salt}${dk.hex()}"


def pbkdf2_verify(password: str, stored: str) -> bool:
    """
    Supports:
    - pbkdf2_sha256$SALT$HASH  (secure)
    - plain$yourpassword       (easy first-time setup)
    """
    try:
        if stored.startswith("plain$"):
            return hmac.compare_digest(password, stored.split("$", 1)[1])

        alg, salt, hexhash = stored.split("$", 2)
        if alg != "pbkdf2_sha256":
            return False
        computed = pbkdf2_hash(password, salt).split("$", 2)[2]
        return hmac.compare_digest(computed, hexhash)
    except Exception:
        return False


# =========================================================
# MIGRATIONS
# =========================================================

def migrate() -> None:
    # Users
    exec_sql("""
    CREATE TABLE IF NOT EXISTS users(
      username TEXT PRIMARY KEY,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'user',
      is_active INTEGER NOT NULL DEFAULT 1,
      created_at TIMESTAMP DEFAULT NOW()
    )
    """)

    # Permissions (optional but you had it in logs)
    exec_sql("""
    CREATE TABLE IF NOT EXISTS permissions(
      id TEXT PRIMARY KEY,
      role TEXT NOT NULL,
      section TEXT NOT NULL,
      can_view INTEGER NOT NULL DEFAULT 0,
      can_add INTEGER NOT NULL DEFAULT 0,
      can_edit INTEGER NOT NULL DEFAULT 0,
      can_delete INTEGER NOT NULL DEFAULT 0,
      can_export INTEGER NOT NULL DEFAULT 0,
      updated_at TIMESTAMP DEFAULT NOW()
    )
    """)

    # Ensure a unique constraint for (role, section) if you use it
    # NOTE: PostgreSQL doesn't support IF NOT EXISTS for ADD CONSTRAINT in old versions,
    # so we do a safe "DO $$" block.
    exec_sql("""
    DO $$
    BEGIN
      IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'permissions_role_section_uniq'
      ) THEN
        ALTER TABLE permissions
        ADD CONSTRAINT permissions_role_section_uniq UNIQUE (role, section);
      END IF;
    END $$;
    """)

    bootstrap_admin_if_needed()


def bootstrap_admin_if_needed() -> None:
    """
    Creates the first admin user if the table is empty and secrets are provided.
    """
    count_row = fetch_one("SELECT COUNT(*) AS c FROM users")
    if not count_row:
        return

    if int(count_row["c"]) > 0:
        return

    admin_user = get_secret("ADMIN_BOOTSTRAP_USER")
    admin_pass = get_secret("ADMIN_BOOTSTRAP_PASSWORD")

    if not admin_user or not admin_pass:
        # No bootstrap secrets: skip quietly
        return

    salt = base64.urlsafe_b64encode(os.urandom(18)).decode("utf-8").rstrip("=")
    pw_hash = pbkdf2_hash(admin_pass, salt)

    exec_sql(
        "INSERT INTO users(username, password_hash, role, is_active) VALUES(:u, :p, 'admin', 1)",
        {"u": admin_user, "p": pw_hash},
    )


# =========================================================
# AUTH UI
# =========================================================

def get_current_user() -> Optional[Dict[str, Any]]:
    return st.session_state.get("auth_user")


def login_ui() -> Optional[Dict[str, Any]]:
    st.subheader("Login")

    username = st.text_input("Username", key="login_username")
    password = st.text_input("Password", type="password", key="login_password")

    col1, col2 = st.columns(2)
    with col1:
        if st.button("Sign in", use_container_width=True):
            user = fetch_one(
                "SELECT username, password_hash, role, is_active FROM users WHERE username=:u",
                {"u": username.strip()},
            )
            if not user or int(user.get("is_active", 0)) != 1:
                st.error("Invalid credentials or disabled account.")
                return None

            if not pbkdf2_verify(password, user["password_hash"]):
                st.error("Invalid credentials or disabled account.")
                return None

            st.session_state["auth_user"] = {
                "username": user["username"],
                "role": user["role"],
            }
            st.success("Logged in")
            st.rerun()

    with col2:
        if st.button("Clear", use_container_width=True):
            st.session_state.pop("login_username", None)
            st.session_state.pop("login_password", None)
            st.rerun()

    return None


def logout_button() -> None:
    if st.button("Logout"):
        st.session_state.pop("auth_user", None)
        st.rerun()


# =========================================================
# ADMIN: CREATE USER (simple)
# =========================================================

def admin_create_user_ui() -> None:
    st.subheader("Admin: Create User")

    u = st.text_input("New Username")
    p = st.text_input("New Password", type="password")
    role = st.selectbox("Role", ["user", "admin"], index=0)
    active = st.checkbox("Active", value=True)

    if st.button("Create User", type="primary"):
        if not u.strip() or not p:
            st.error("Username and password are required.")
            return

        exists = fetch_one("SELECT username FROM users WHERE username=:u", {"u": u.strip()})
        if exists:
            st.error("User already exists.")
            return

        salt = base64.urlsafe_b64encode(os.urandom(18)).decode("utf-8").rstrip("=")
        pw_hash = pbkdf2_hash(p, salt)

        exec_sql(
            "INSERT INTO users(username, password_hash, role, is_active) VALUES(:u, :p, :r, :a)",
            {"u": u.strip(), "p": pw_hash, "r": role, "a": 1 if active else 0},
        )
        st.success(f"Created user: {u.strip()}")


# =========================================================
# MAIN APP
# =========================================================

def main_app() -> None:
    st.title("The AdBook – AIAMS")

    user = get_current_user()
    if not user:
        login_ui()
        st.info("If this is your first run: set ADMIN_BOOTSTRAP_USER/PASSWORD in Secrets, then login.")
        return

    st.success(f"Logged in as {user['username']} ({user['role']})")
    logout_button()
    st.divider()

    if user["role"] == "admin":
        admin_create_user_ui()
        st.divider()

    st.write("✅ App is running and database is connected.")


# =========================================================
# ENTRYPOINT
# =========================================================

if __name__ == "__main__":
    try:
        migrate()
        main_app()
    except Exception as e:
        # Friendly error – real details go to logs
        st.error("App error. Please check Streamlit logs (Manage app → Logs).")
        st.exception(e)
