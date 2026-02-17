import os
import uuid
import hashlib
import base64
import streamlit as st
import pandas as pd
from sqlalchemy import create_engine, text

# ---------------- PAGE CONFIG ----------------
st.set_page_config(page_title="The Adbook AIAMS v9.0", layout="wide")

st.title("The Adbook AIAMS v9.0")
st.caption("Cloud DB + Dual Modules + RBAC")

# ---------------- DATABASE ENGINE (SUPABASE SAFE) ----------------
@st.cache_resource(show_spinner=False)
def engine():
    db_url = (os.environ.get("DATABASE_URL") or "").strip()

    if not db_url:
        st.error("❌ DATABASE_URL not set in Streamlit Secrets.")
        st.stop()

    # Force psycopg v3 driver
    if db_url.startswith("postgresql://"):
        db_url = db_url.replace("postgresql://", "postgresql+psycopg://", 1)

    # Ensure SSL required for Supabase
    if "sslmode=" not in db_url:
        db_url += ("&" if "?" in db_url else "?") + "sslmode=require"

    return create_engine(db_url, pool_pre_ping=True)

def exec_sql(sql, params=None):
    with engine().begin() as conn:
        conn.execute(text(sql), params or {})

def qdf(sql, params=None):
    with engine().connect() as conn:
        return pd.read_sql(text(sql), conn, params=params or {})

# ---------------- PASSWORD HASH ----------------
def pbkdf2_hash(password: str, salt: str | None = None):
    salt = salt or uuid.uuid4().hex
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 120_000)
    return f"pbkdf2_sha256${salt}${base64.b64encode(dk).decode()}"

def pbkdf2_verify(password, stored):
    try:
        alg, salt, b64hash = stored.split("$", 2)
        if alg != "pbkdf2_sha256":
            return False
        return pbkdf2_hash(password, salt).split("$", 2)[2] == b64hash
    except:
        return False

# ---------------- MIGRATIONS ----------------
def migrate():
    exec_sql("""
    CREATE TABLE IF NOT EXISTS users(
      username TEXT PRIMARY KEY,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL,
      section_scope TEXT DEFAULT '*',
      is_active INTEGER DEFAULT 1,
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
      can_view INTEGER DEFAULT 1,
      can_add INTEGER DEFAULT 0,
      can_edit INTEGER DEFAULT 0,
      can_delete INTEGER DEFAULT 0,
      can_export INTEGER DEFAULT 0
    )
    """)

# ---------------- ADMIN BOOTSTRAP ----------------
def bootstrap_admin():
    admin_u = os.environ.get("ADMIN_USERNAME", "admin")
    admin_p = os.environ.get("ADMIN_PASSWORD", "admin@123")

    df = qdf("SELECT username FROM users WHERE username=:u", {"u": admin_u})

    if len(df) == 0:
        exec_sql("""
        INSERT INTO users(username,password_hash,role,section_scope,is_active)
        VALUES(:u,:p,'Super Admin','*',1)
        """, {"u": admin_u, "p": pbkdf2_hash(admin_p)})

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
