import os
import re
import io
import uuid
import json
import hashlib
from datetime import date, timedelta
from urllib.parse import quote_plus

import numpy as np
import pandas as pd
import streamlit as st

from xhtml2pdf import pisa
from sqlalchemy import create_engine, text

APP_TITLE = "The Adbook — AIAMS v8.1 (Supabase)"
WEBSITE_URL = "https://theadbookoutdoor.com/"
DATA_FILE = "property_data.csv"

# ---------------- UI ----------------
st.set_page_config(page_title=APP_TITLE, layout="wide", page_icon="🟧")

st.markdown(
    """
<style>
.block-container{max-width:1560px;padding-top:.65rem;padding-bottom:2rem;}
[data-testid="stSidebar"]{background:#f6f8fb;border-right:1px solid #e6e8ef;}
.card{background:#fff;border:1px solid #e6e8ef;border-radius:18px;padding:14px;box-shadow:0 8px 24px rgba(15,23,42,.06);}
.kpi{background:#fff;border:1px solid #e6e8ef;border-radius:16px;padding:10px 12px;}
.kpi .label{color:#475569;font-size:.85rem;margin-bottom:2px;}
.kpi .val{font-weight:850;font-size:1.25rem;color:#0f172a;}
.section{font-weight:850;font-size:1.05rem;margin:0 0 .25rem 0;}
.small{color:#475569;font-size:.92rem;}
.sticky-wrap{position:sticky;top:0;z-index:999;background:rgba(255,255,255,.96);
  border-bottom:1px solid #e6e8ef;padding:8px 0 10px 0;margin-bottom:10px;}
</style>
""",
    unsafe_allow_html=True,
)

# ---------------- Constants ----------------
SECTION_INSTALL = "Installation"
SECTION_ADS = "Advertisement"

ROLE_SUPERADMIN = "SuperAdmin"
ROLE_HEAD = "HeadOps"
ROLE_INSTALL_FIELD = "InstallField"
ROLE_ADS_FIELD = "AdsField"
ROLE_VIEWER = "Viewer"
ROLE_EXECUTIVE = "Executive"

ROLE_LABEL = {
    ROLE_EXECUTIVE: "Executive / CEO (Read-only dashboards)",
    ROLE_SUPERADMIN: "Super Admin (All)",
    ROLE_HEAD: "Head of Ops (All)",
    ROLE_INSTALL_FIELD: "Field Team (Installation)",
    ROLE_ADS_FIELD: "Field Team (Advertisement)",
    ROLE_VIEWER: "Viewer (Read-only)",
}

DEFAULT_PERMS = {
    ROLE_SUPERADMIN: {"*": {"view": 1, "add": 1, "edit": 1, "delete": 1, "export": 1}},
    ROLE_HEAD: {"*": {"view": 1, "add": 1, "edit": 1, "delete": 0, "export": 1}},
    ROLE_VIEWER: {"*": {"view": 1, "add": 0, "edit": 0, "delete": 0, "export": 0}},
    ROLE_EXECUTIVE: {"*": {"view": 1, "add": 0, "edit": 0, "delete": 0, "export": 1}},
    ROLE_INSTALL_FIELD: {SECTION_INSTALL: {"view": 1, "add": 1, "edit": 1, "delete": 0, "export": 0}},
    ROLE_ADS_FIELD: {SECTION_ADS: {"view": 1, "add": 1, "edit": 1, "delete": 0, "export": 0}},
}

# Upload folders
UPLOAD_ROOT = "uploads_docs"
UPLOAD_INSTALL = os.path.join(UPLOAD_ROOT, "installation")
UPLOAD_ADS = os.path.join(UPLOAD_ROOT, "advertisement")
UPLOAD_SIG = os.path.join(UPLOAD_ROOT, "signatures")
os.makedirs(UPLOAD_INSTALL, exist_ok=True)
os.makedirs(UPLOAD_ADS, exist_ok=True)
os.makedirs(UPLOAD_SIG, exist_ok=True)

# ---------------- DB Connection (Supabase) ----------------
def get_database_url() -> str:
    """
    Priority:
    1) Streamlit secrets: st.secrets["DATABASE_URL"]
    2) Environment variable: DATABASE_URL
    """
    try:
        if "DATABASE_URL" in st.secrets:
            return str(st.secrets["DATABASE_URL"]).strip()
    except Exception:
        pass
    return os.environ.get("DATABASE_URL", "").strip()

@st.cache_resource(show_spinner=False)
def engine():
    db_url = get_database_url()
    if not db_url:
        st.error("DATABASE_URL not found. Add it in .streamlit/secrets.toml or as env var DATABASE_URL.")
        st.stop()
    # Supabase Postgres uses SSL; SQLAlchemy can handle it via the URL / server defaults.
    return create_engine(db_url, pool_pre_ping=True)

def exec_sql(sql: str, params: dict | None = None):
    with engine().begin() as conn:
        conn.execute(text(sql), params or {})

def qdf(sql: str, params: dict | None = None) -> pd.DataFrame:
    with engine().connect() as conn:
        return pd.read_sql(text(sql), conn, params=params or {})

# ---------------- Migrations ----------------
def migrate():
    exec_sql("""
    CREATE TABLE IF NOT EXISTS users(
      username TEXT PRIMARY KEY,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL,
      section_scope TEXT NOT NULL DEFAULT 'Both',
      is_active INTEGER NOT NULL DEFAULT 1,
      created_at TIMESTAMP DEFAULT NOW(),
      updated_at TIMESTAMP DEFAULT NOW(),
      last_login_at TIMESTAMP
    )
    """)

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

    exec_sql("""
    CREATE TABLE IF NOT EXISTS audit_logs(
      log_id TEXT PRIMARY KEY,
      username TEXT,
      action_type TEXT,
      details TEXT,
      created_at TIMESTAMP DEFAULT NOW()
    )
    """)

    exec_sql("""
    CREATE TABLE IF NOT EXISTS property_codes(
      property_id TEXT PRIMARY KEY,
      property_code TEXT UNIQUE,
      district TEXT,
      city TEXT,
      property_name TEXT,
      created_at TIMESTAMP DEFAULT NOW()
    )
    """)

    # FIX: composite PK so Installation and Advertisement can both store same record_hash
    exec_sql("""
    CREATE TABLE IF NOT EXISTS lead_updates_v8(
      record_hash TEXT NOT NULL,
      section TEXT NOT NULL,
      status TEXT,
      assigned_to TEXT,
      lead_source TEXT,
      notes TEXT,
      follow_up TEXT,
      last_call_outcome TEXT,
      last_call_at TIMESTAMP,
      last_updated TIMESTAMP DEFAULT NOW(),
      PRIMARY KEY(record_hash, section)
    )
    """)

    exec_sql("""
    CREATE TABLE IF NOT EXISTS inventory_sites_v8(
      property_id TEXT PRIMARY KEY,
      property_code TEXT,
      district TEXT,
      city TEXT,
      property_name TEXT,
      property_address TEXT,
      no_screens_installed INTEGER DEFAULT 0,
      agreed_rent_pm REAL,
      notes TEXT,
      last_updated TIMESTAMP DEFAULT NOW()
    )
    """)

    exec_sql("""
    CREATE TABLE IF NOT EXISTS screens_v8(
      screen_id TEXT PRIMARY KEY,
      property_id TEXT NOT NULL,
      screen_location TEXT,
      installed_date TEXT,
      installed_by TEXT,
      last_service_date TEXT,
      next_service_due TEXT,
      is_active INTEGER DEFAULT 1,
      last_updated TIMESTAMP DEFAULT NOW()
    )
    """)

    exec_sql("""
    CREATE TABLE IF NOT EXISTS proposals_v8(
      proposal_id TEXT PRIMARY KEY,
      section TEXT NOT NULL,
      property_id TEXT,
      advertiser_id TEXT,
      proposal_no INTEGER NOT NULL,
      created_by TEXT,
      created_at TIMESTAMP DEFAULT NOW(),
      pdf_filename TEXT,
      status TEXT
    )
    """)

    exec_sql("""
    CREATE TABLE IF NOT EXISTS company_settings_v8(
      settings_id TEXT PRIMARY KEY,
      gst_no TEXT,
      bank_details TEXT,
      whatsapp_limit_per_hour INTEGER DEFAULT 50,
      updated_at TIMESTAMP DEFAULT NOW()
    )
    """)

    exec_sql("""
    CREATE TABLE IF NOT EXISTS user_profiles_v8(
      username TEXT PRIMARY KEY,
      signature_filename TEXT,
      designation TEXT,
      mobile TEXT,
      email TEXT,
      updated_at TIMESTAMP DEFAULT NOW()
    )
    """)

migrate()

# ---------------- Security ----------------
def pbkdf2_hash(password: str, salt: str | None = None) -> str:
    import hashlib as _hashlib
    salt = salt or uuid.uuid4().hex
    dk = _hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 120_000)
    return f"pbkdf2_sha256${salt}${dk.hex()}"

def pbkdf2_verify(password: str, stored: str) -> bool:
    try:
        alg, salt, hexhash = stored.split("$", 2)
        if alg != "pbkdf2_sha256":
            return False
        return pbkdf2_hash(password, salt).split("$", 2)[2] == hexhash
    except Exception:
        return False

def audit(user, action, details=""):
    exec_sql(
        "INSERT INTO audit_logs(log_id,username,action_type,details) VALUES(:id,:u,:a,:d)",
        {"id": str(uuid.uuid4()), "u": user, "a": action, "d": details},
    )

def get_user(username):
    df = qdf("SELECT * FROM users WHERE username=:u", {"u": username})
    return df.iloc[0].to_dict() if len(df) else None

def set_last_login(username):
    exec_sql("UPDATE users SET last_login_at=NOW(), updated_at=NOW() WHERE username=:u", {"u": username})

# ---------------- Permissions ----------------
@st.cache_data(show_spinner=False)
def load_permissions():
    return qdf("SELECT role, section, can_view, can_add, can_edit, can_delete, can_export FROM permissions")

def can(section: str, action: str, role: str) -> bool:
    if role == ROLE_SUPERADMIN:
        return True
    perms = load_permissions()
    sub = perms[(perms["role"] == role) & (perms["section"].isin([section, "*"]))]
    if len(sub) == 0:
        return action == "view" and role == ROLE_VIEWER
    spec = sub[sub["section"] == section]
    row = (spec.iloc[0] if len(spec) else sub.iloc[0]).to_dict()
    return bool(row.get(f"can_{action}", 0))

def seed_permissions_once():
    df = qdf("SELECT COUNT(*) AS c FROM permissions")
    c = int(df.iloc[0]["c"] or 0)
    if c == 0:
        for role, sections in DEFAULT_PERMS.items():
            for sec, perm in sections.items():
                exec_sql(
                    """INSERT INTO permissions(id,role,section,can_view,can_add,can_edit,can_delete,can_export)
                       VALUES(:id,:role,:section,:v,:a,:e,:d,:x)""",
                    {
                        "id": str(uuid.uuid4()),
                        "role": role,
                        "section": sec,
                        "v": int(perm["view"]),
                        "a": int(perm["add"]),
                        "e": int(perm["edit"]),
                        "d": int(perm["delete"]),
                        "x": int(perm["export"]),
                    },
                )

seed_permissions_once()

# ---------------- Data helpers ----------------
@st.cache_data(show_spinner=False)
def read_leads_file(upload=None):
    if upload is None:
        df = pd.read_csv(DATA_FILE, encoding="utf-8-sig", low_memory=False)
    else:
        name = upload.name.lower()
        if name.endswith(".csv"):
            df = pd.read_csv(upload, encoding="utf-8-sig", low_memory=False)
        else:
            xl = pd.ExcelFile(upload)
            sheet = st.selectbox("Sheet", xl.sheet_names, key="upload_sheet_v8")
            df = pd.read_excel(upload, sheet_name=sheet)
    df.columns = [c.strip() for c in df.columns]
    if "District Type" in df.columns and "City" not in df.columns:
        df = df.rename(columns={"District Type": "City"})
    return df

def norm(x):
    if x is None or (isinstance(x, float) and np.isnan(x)):
        return ""
    return str(x).strip()

def normalize_mobile(x):
    x = "" if x is None else str(x)
    x = re.sub(r"[^0-9+]", "", x).replace("+91", "")
    x = re.sub(r"\D", "", x)
    if len(x) > 10:
        x = x[-10:]
    return x

def make_hash(prop, addr, dist, city, mobile, email):
    s = "||".join([prop, addr, dist, city, mobile, email]).lower().encode("utf-8", errors="ignore")
    return hashlib.sha256(s).hexdigest()

def kpi(label, value):
    st.markdown(
        f"<div class='kpi'><div class='label'>{label}</div><div class='val'>{value}</div></div>",
        unsafe_allow_html=True,
    )

# ---------------- Lead update UPSERT (Postgres) ----------------
def upsert_lead_update(section, record_hash, status, assigned_to, lead_source, notes, follow_up, last_call_outcome=None):
    exec_sql(
        """
        INSERT INTO lead_updates_v8(record_hash,section,status,assigned_to,lead_source,notes,follow_up,last_call_outcome,last_call_at,last_updated)
        VALUES(:h,:s,:st,:as,:src,:n,:fu,:out,CASE WHEN :out IS NULL THEN NULL ELSE NOW() END,NOW())
        ON CONFLICT(record_hash, section) DO UPDATE SET
          status=EXCLUDED.status,
          assigned_to=EXCLUDED.assigned_to,
          lead_source=EXCLUDED.lead_source,
          notes=EXCLUDED.notes,
          follow_up=EXCLUDED.follow_up,
          last_call_outcome=COALESCE(EXCLUDED.last_call_outcome, lead_updates_v8.last_call_outcome),
          last_call_at=CASE WHEN EXCLUDED.last_call_outcome IS NULL THEN lead_updates_v8.last_call_at ELSE NOW() END,
          last_updated=NOW()
        """,
        {"h": record_hash, "s": section, "st": status, "as": assigned_to, "src": lead_source, "n": notes, "fu": follow_up, "out": last_call_outcome},
    )

# ---------------- Login ----------------
def require_auth():
    if "auth" in st.session_state:
        return
    with st.sidebar:
        st.markdown("### 🔐 Login")
        u = st.text_input("Username", key="login_u").strip()
        p = st.text_input("Password", type="password", key="login_p")
        if st.button("Login", type="primary", use_container_width=True):
            row = get_user(u)
            if row and int(row.get("is_active", 0) or 0) == 1 and pbkdf2_verify(p, row["password_hash"]):
                st.session_state["auth"] = {"user": row["username"], "role": row["role"], "scope": row["section_scope"]}
                set_last_login(row["username"])
                audit(row["username"], "LOGIN", f"role={row['role']} scope={row['section_scope']}")
                st.rerun()
            st.error("Invalid credentials or disabled account.")
        st.stop()

require_auth()

AUTH = st.session_state["auth"]
USER = AUTH["user"]
ROLE = AUTH["role"]
SCOPE = AUTH.get("scope", "Both")

# ---------------- Sidebar ----------------
with st.sidebar:
    st.markdown("### AIAMS v8.1")
    st.markdown(f"**User:** {USER}")
    st.markdown(f"**Role:** {ROLE_LABEL.get(ROLE, ROLE)}")
    st.markdown("---")

    data_mode = st.radio("Data Source", ["Bundled (CSV)", "Upload Excel/CSV"], index=0)
    upload = None
    if data_mode == "Upload Excel/CSV":
        upload = st.file_uploader("Upload file", type=["csv", "xlsx", "xls"])
        if not upload:
            st.stop()

    allowed_sections = [SECTION_INSTALL, SECTION_ADS] if SCOPE == "Both" else [SCOPE]
    SECTION = st.radio("Module", allowed_sections, horizontal=True)

# ---------------- Load Leads ----------------
leads_df = read_leads_file(upload).copy()

# Ensure columns exist
for col in ["District", "City", "Property Name", "Property Address", "Promoter Mobile Number", "Promoter Email", "Promoter / Developer Name"]:
    if col not in leads_df.columns:
        leads_df[col] = ""

leads_df["__hash"] = [
    make_hash(
        norm(r.get("Property Name")),
        norm(r.get("Property Address")),
        norm(r.get("District")),
        norm(r.get("City")),
        normalize_mobile(r.get("Promoter Mobile Number")),
        norm(r.get("Promoter Email")),
    )
    for r in leads_df.to_dict("records")
]

# Merge updates
upd = qdf("SELECT * FROM lead_updates_v8 WHERE section=:s", {"s": SECTION})
leads_df = leads_df.merge(upd, left_on="__hash", right_on="record_hash", how="left")
leads_df["status"] = leads_df["status"].fillna("New")
leads_df["assigned_to"] = leads_df["assigned_to"].fillna("")
leads_df["lead_source"] = leads_df["lead_source"].fillna("")
leads_df["notes"] = leads_df["notes"].fillna("")
leads_df["follow_up"] = leads_df["follow_up"].fillna("")

# Role filter
if ROLE in [ROLE_INSTALL_FIELD, ROLE_ADS_FIELD, ROLE_VIEWER]:
    leads_df = leads_df[leads_df["assigned_to"].astype("string") == USER]

# ---------------- Top KPIs ----------------
st.markdown("<div class='sticky-wrap'>", unsafe_allow_html=True)
c1, c2, c3, c4 = st.columns(4)
with c1: kpi("Leads", f"{len(leads_df):,}")
with c2: kpi("New", f"{int((leads_df['status']=='New').sum()):,}")
with c3: kpi("Follow-up", f"{int((leads_df['status']=='Follow-up Required').sum()):,}")
with c4: kpi("Interested", f"{int((leads_df['status']=='Interested').sum()):,}")
st.markdown("</div>", unsafe_allow_html=True)

# ---------------- Simple Home Page (Working demo) ----------------
st.markdown("<div class='card'><div class='section'>Home (Search & Update)</div><div class='small'>This is a working minimal page to confirm Supabase connection is OK.</div></div>", unsafe_allow_html=True)

q = st.text_input("Search property name / district / city", "")
f = leads_df.copy()
if q.strip():
    s = q.strip().lower()
    f = f[
        f["Property Name"].astype("string").str.lower().str.contains(s, na=False)
        | f["District"].astype("string").str.lower().str.contains(s, na=False)
        | f["City"].astype("string").str.lower().str.contains(s, na=False)
    ]

st.write(f"Showing {len(f):,} leads")
st.dataframe(f[["Property Name", "District", "City", "Promoter / Developer Name", "Promoter Mobile Number", "Promoter Email", "status", "assigned_to"]], use_container_width=True, height=420)

st.markdown("### Update one lead")
if len(f):
    idx = st.number_input("Pick row number (0-based)", min_value=0, max_value=max(0, len(f)-1), value=0, step=1)
    row = f.iloc[int(idx)]
    st.caption(f"Selected: {row.get('Property Name','')} — {row.get('District','')} / {row.get('City','')}")

    col1, col2 = st.columns(2)
    with col1:
        new_status = st.selectbox("Status", ["New","Contacted","Follow-up Required","Interested","Installed","Active","Rejected/Not Suitable"], index=0)
        new_assigned = st.text_input("Assigned to", value=str(row.get("assigned_to","")))
    with col2:
        new_source = st.text_input("Lead source", value=str(row.get("lead_source","")))
        new_follow = st.text_input("Follow-up date/note", value=str(row.get("follow_up","")))

    new_notes = st.text_area("Notes", value=str(row.get("notes","")), height=110)

    if st.button("Save Update", type="primary"):
        upsert_lead_update(
            section=SECTION,
            record_hash=str(row["__hash"]),
            status=new_status,
            assigned_to=new_assigned,
            lead_source=new_source,
            notes=new_notes,
            follow_up=new_follow,
            last_call_outcome=None
        )
        audit(USER, "LEAD_UPDATE", f"section={SECTION} hash={row['__hash']} status={new_status}")
        st.success("Saved to Supabase.")
        st.cache_data.clear()
        st.rerun()
else:
    st.warning("No rows to update based on your search.")
