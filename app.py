import os
import uuid
import hashlib
import base64
from datetime import datetime

import streamlit as st
import pandas as pd
from sqlalchemy import create_engine, text


# ---------------- UI config ----------------
st.set_page_config(page_title="The Adbook AIAMS v9.0", layout="wide")

LOGO_PATH = "assets/logo.png"
if os.path.exists(LOGO_PATH):
    st.image(LOGO_PATH, width=180)
else:
    st.caption("ℹ️ Logo not found at assets/logo.png (app will still run).")

st.title("The Adbook AIAMS v9.0")
st.caption("Cloud DB (Supabase) + Dual Modules + RBAC Starter")


# ---------------- Password hashing (PBKDF2) ----------------
def pbkdf2_hash(password: str, salt: str | None = None, iterations: int = 120_000) -> str:
    salt = salt or uuid.uuid4().hex
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), iterations)
    return f"pbkdf2_sha256${iterations}${salt}${base64.b64encode(dk).decode('utf-8')}"

def pbkdf2_verify(password: str, stored: str) -> bool:
    try:
        alg, iters, salt, b64hash = stored.split("$", 3)
        if alg != "pbkdf2_sha256":
            return False
        iters = int(iters)
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), iters)
        return base64.b64encode(dk).decode("utf-8") == b64hash
    except Exception:
        return False


# ---------------- DB ----------------
def get_database_url() -> str:
    # Streamlit Cloud Secrets become environment vars
    return (os.environ.get("DATABASE_URL") or "").strip()

@st.cache_resource(show_spinner=False)
def engine():
    db_url = get_database_url()
    if not db_url:
        # If you see this on Streamlit Cloud, it means Secrets not saved correctly
        return create_engine("sqlite:///aiams.db", connect_args={"check_same_thread": False})
    return create_engine(db_url, pool_pre_ping=True)

def exec_sql(sql: str, params: dict | None = None):
    with engine().begin() as conn:
        conn.execute(text(sql), params or {})

def qdf(sql: str, params: dict | None = None) -> pd.DataFrame:
    with engine().connect() as conn:
        return pd.read_sql(text(sql), conn, params=params or {})

def migrate():
    # users table
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

    # permissions matrix
    exec_sql("""
    CREATE TABLE IF NOT EXISTS permissions(
      id TEXT PRIMARY KEY,
      role TEXT NOT NULL,
      section TEXT NOT NULL,
      can_view INTEGER NOT NULL DEFAULT 1,
      can_add INTEGER NOT NULL DEFAULT 0,
      can_edit INTEGER NOT NULL DEFAULT 0,
      can_delete INTEGER NOT NULL DEFAULT 0,
      can_export INTEGER NOT NULL DEFAULT 0,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    # round robin rules
    exec_sql("""
    CREATE TABLE IF NOT EXISTS lead_assignment_rules(
      rule_id TEXT PRIMARY KEY,
      section TEXT NOT NULL,
      district TEXT NOT NULL,
      city TEXT NOT NULL,
      assignees_json TEXT NOT NULL,
      last_index INTEGER NOT NULL DEFAULT -1,
      is_enabled INTEGER NOT NULL DEFAULT 1,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

def bootstrap_admin():
    admin_u = os.environ.get("ADMIN_USERNAME", "admin").strip()
    admin_p = os.environ.get("ADMIN_PASSWORD", "admin@123").strip()

    df = qdf("SELECT username FROM users WHERE username=:u", {"u": admin_u})
    if len(df) == 0:
        exec_sql("""
        INSERT INTO users(username, password_hash, role, section_scope, is_active)
        VALUES(:u, :p, 'Super Admin', '*', 1)
        """, {"u": admin_u, "p": pbkdf2_hash(admin_p)})

    # If permissions empty, seed minimal defaults
    pc = qdf("SELECT COUNT(*) AS c FROM permissions").iloc[0]["c"]
    if int(pc) == 0:
        defaults = [
            ("Super Admin", "*", 1, 1, 1, 1, 1),
            ("Head Ops", "*", 1, 1, 1, 0, 1),
            ("Installation Manager", "Installation", 1, 1, 1, 0, 1),
            ("Advertisement Manager", "Advertisement", 1, 1, 1, 0, 1),
            ("Field Team (Installation)", "Installation", 1, 1, 1, 0, 0),
            ("Field Team (Advertisement)", "Advertisement", 1, 1, 1, 0, 0),
            ("Viewer", "*", 1, 0, 0, 0, 0),
        ]
        for role, section, v,a,e,d,x in defaults:
            exec_sql("""
            INSERT INTO permissions(id, role, section, can_view, can_add, can_edit, can_delete, can_export)
            VALUES(:id,:r,:s,:v,:a,:e,:d,:x)
            """, {
                "id": str(uuid.uuid4()), "r": role, "s": section,
                "v": v, "a": a, "e": e, "d": d, "x": x
            })

# Run migrations early (important)
migrate()
bootstrap_admin()


# ---------------- Auth ----------------
def get_user(username: str):
    df = qdf("SELECT * FROM users WHERE username=:u", {"u": username})
    return df.iloc[0].to_dict() if len(df) else None

def set_last_login(username: str):
    exec_sql("UPDATE users SET last_login_at=CURRENT_TIMESTAMP, updated_at=CURRENT_TIMESTAMP WHERE username=:u", {"u": username})

def require_auth():
    if "auth" in st.session_state:
        return

    with st.sidebar:
        st.markdown("### 🔐 Login")
        u = st.text_input("Username", key="login_u")
        p = st.text_input("Password", type="password", key="login_p")
        if st.button("Login", type="primary", use_container_width=True):
            row = get_user(u.strip())
            if row and int(row.get("is_active", 0) or 0) == 1 and pbkdf2_verify(p, row["password_hash"]):
                st.session_state["auth"] = {
                    "user": row["username"],
                    "role": row["role"],
                    "scope": row.get("section_scope", "*")
                }
                set_last_login(row["username"])
                st.rerun()
            st.error("Invalid credentials or disabled account.")
        st.caption("Default admin is created from Secrets: ADMIN_USERNAME / ADMIN_PASSWORD")
        st.stop()

require_auth()

AUTH = st.session_state["auth"]
USER = AUTH["user"]
ROLE = AUTH["role"]
SCOPE = AUTH.get("scope", "*")


# ---------------- Permissions ----------------
@st.cache_data(show_spinner=False)
def load_permissions():
    return qdf("SELECT role, section, can_view, can_add, can_edit, can_delete, can_export FROM permissions")

def can(section: str, action: str) -> bool:
    if ROLE == "Super Admin":
        return True
    perms = load_permissions()
    sub = perms[(perms["role"] == ROLE) & (perms["section"].isin([section, "*"]))]
    if len(sub) == 0:
        return action == "view" and ROLE == "Viewer"
    # prefer exact section match
    spec = sub[sub["section"] == section]
    row = (spec.iloc[0] if len(spec) else sub.iloc[0]).to_dict()
    return bool(int(row.get(f"can_{action}", 0) or 0))


# ---------------- App Navigation (Dual Module menus) ----------------
st.sidebar.markdown("---")
st.sidebar.markdown(f"**Logged in:** {USER}")
st.sidebar.caption(f"Role: {ROLE} | Scope: {SCOPE}")

MENU = st.sidebar.radio("Navigation", ["Dashboard", "Installation", "Advertisement", "Admin Panel", "Logout"])

if MENU == "Logout":
    st.session_state.pop("auth", None)
    st.rerun()

if MENU == "Dashboard":
    st.subheader("Overview Dashboard")
    st.info("Next: KPIs + charts + due reminders + top priority leads.")

elif MENU == "Installation":
    section = "Installation"
    sub = st.sidebar.selectbox("Installation Menu", [
        "Leads", "Inventory", "Screens", "Service Center",
        "Installation Agreements", "Installation Documents", "Reports"
    ])
    if not can(section, "view"):
        st.error("No access.")
    else:
        st.subheader(f"Installation → {sub}")
        st.caption("Next: Build each screen with DB tables.")

elif MENU == "Advertisement":
    section = "Advertisement"
    sub = st.sidebar.selectbox("Advertisement Menu", [
        "Leads", "Advertisers", "Ad Inventory", "Screen Allotment",
        "Ads Agreements", "Billing & Reminders", "Ads Documents", "Reports"
    ])
    if not can(section, "view"):
        st.error("No access.")
    else:
        st.subheader(f"Advertisement → {sub}")
        st.caption("Next: Build each screen with DB tables.")

elif MENU == "Admin Panel":
    if ROLE not in ["Super Admin", "Head Ops"]:
        st.error("Admin Panel is restricted.")
    else:
        sub = st.sidebar.selectbox("Admin Menu", [
            "Users", "Permissions Matrix", "Round Robin Rules", "System Settings"
        ])
        st.subheader(f"Admin → {sub}")

        if sub == "Users":
            st.write(qdf("SELECT username, role, section_scope, is_active, created_at FROM users ORDER BY username"))

        elif sub == "Permissions Matrix":
            st.write(load_permissions())

        elif sub == "Round Robin Rules":
            st.write(qdf("SELECT * FROM lead_assignment_rules ORDER BY section, district, city"))

        elif sub == "System Settings":
            st.info("Next: GST / Bank / WhatsApp limits / branding.")
