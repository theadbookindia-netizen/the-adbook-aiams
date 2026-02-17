import os
import uuid
import hashlib
import base64
import streamlit as st
import pandas as pd
from sqlalchemy import create_engine, text

st.set_page_config(page_title="The Adbook AIAMS v9.0", layout="wide")

# ---------- DB ENGINE ----------
@st.cache_resource(show_spinner=False)
def engine():
    db_url = (os.environ.get("DATABASE_URL") or "").strip()
    if not db_url:
        st.error("❌ DATABASE_URL missing in Secrets.")
        st.stop()

    # Force psycopg v3 driver
    if db_url.startswith("postgresql://"):
        db_url = db_url.replace("postgresql://", "postgresql+psycopg://", 1)

    # Ensure SSL
    if "sslmode=" not in db_url:
        db_url += ("&" if "?" in db_url else "?") + "sslmode=require"

    return create_engine(
        db_url,
        pool_pre_ping=True,
        pool_size=2,
        max_overflow=3,
        pool_recycle=180,
    )
# ---------- MIGRATIONS ----------
def migrate():
    exec_sql("""
    CREATE TABLE IF NOT EXISTS users(
      username TEXT PRIMARY KEY,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL,
      section_scope TEXT NOT NULL DEFAULT '*',
      is_active INTEGER NOT NULL DEFAULT 1,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      last_login_at TIMESTAMP
    )
    """)

    exec_sql("""
    CREATE TABLE IF NOT EXISTS permissions(
      id TEXT PRIMARY KEY,
      role TEXT NOT NULL,
      section TEXT NOT NULL,
      can_view INTEGER NOT NULL DEFAULT 1,
      can_add INTEGER NOT NULL DEFAULT 0,
      can_edit INTEGER NOT NULL DEFAULT 0,
      can_delete INTEGER NOT NULL DEFAULT 0,
      can_export INTEGER NOT NULL DEFAULT 0
    )
    """)

    exec_sql("""
    CREATE TABLE IF NOT EXISTS lead_assignment_rules(
      rule_id TEXT PRIMARY KEY,
      section TEXT NOT NULL,
      district TEXT NOT NULL,
      city TEXT NOT NULL,
      assignees_json TEXT NOT NULL,
      last_index INTEGER NOT NULL DEFAULT -1,
      is_enabled INTEGER NOT NULL DEFAULT 1
    )
    """)
def test_db():
    try:
        with engine().connect() as conn:
            conn.execute(text("SELECT 1"))
        st.success("✅ Database connected successfully.")
    except Exception as e:
        st.error("❌ Database connection failed. Check Secrets DATABASE_URL + Supabase status.")
        st.exception(e)   # shows real reason in logs
        st.stop()

test_db()
migrate()
bootstrap_admin()

# ---------------- AUTH ----------------
def get_user(username):
    df = qdf("SELECT * FROM users WHERE username=:u", {"u": username})
    return df.iloc[0].to_dict() if len(df) else None

def require_auth():
    if "auth" in st.session_state:
        return

    st.sidebar.markdown("### 🔐 Login")
    u = st.sidebar.text_input("Username")
    p = st.sidebar.text_input("Password", type="password")

    if st.sidebar.button("Login"):
        row = get_user(u.strip())
        if row and int(row["is_active"]) == 1 and pbkdf2_verify(p, row["password_hash"]):
            st.session_state["auth"] = row
            st.rerun()
        st.sidebar.error("Invalid credentials.")

    st.stop()

require_auth()

USER = st.session_state["auth"]["username"]
ROLE = st.session_state["auth"]["role"]

st.sidebar.markdown("---")
st.sidebar.write(f"👤 {USER}")
st.sidebar.write(f"Role: {ROLE}")

# ---------------- NAVIGATION ----------------
menu = st.sidebar.radio("Navigation", [
    "Dashboard",
    "Installation",
    "Advertisement",
    "Admin Panel",
    "Logout"
])

if menu == "Logout":
    st.session_state.pop("auth", None)
    st.rerun()

if menu == "Dashboard":
    st.subheader("Dashboard")
    st.info("KPIs will appear here.")

elif menu == "Installation":
    sub = st.sidebar.selectbox("Installation Menu", [
        "Leads", "Inventory", "Screens",
        "Service Center", "Agreements",
        "Documents", "Reports"
    ])
    st.subheader(f"Installation → {sub}")

elif menu == "Advertisement":
    sub = st.sidebar.selectbox("Advertisement Menu", [
        "Leads", "Advertisers", "Ad Inventory",
        "Screen Allotment", "Agreements",
        "Billing", "Documents", "Reports"
    ])
    st.subheader(f"Advertisement → {sub}")

elif menu == "Admin Panel":
    if ROLE not in ["Super Admin"]:
        st.error("Restricted.")
    else:
        st.subheader("Admin Panel")
        st.write(qdf("SELECT username, role, is_active FROM users"))
