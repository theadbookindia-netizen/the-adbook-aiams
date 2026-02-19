import os
import re
import io
import uuid
import hashlib
from datetime import date, timedelta
from pathlib import Path
from urllib.parse import quote_plus
from io import BytesIO

import numpy as np
import pandas as pd
import streamlit as st
from sqlalchemy import create_engine, text
from sqlalchemy.exc import SQLAlchemyError

# ---- PDF (Cloud-safe) ----
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas


# =========================================================
# BASIC CONFIG
# =========================================================
APP_TITLE = "The Adbook — AIAMS (Supabase)"
WEBSITE_URL = "https://theadbookoutdoor.com/"
DATA_FILE = "property_data.csv"
LOGO_PATH = "assets/logo.png"

SECTION_INSTALL = "Installation"
SECTION_ADS = "Advertisement"
SCOPE_BOTH = "Both"

ROLE_SUPERADMIN = "SuperAdmin"
ROLE_HEAD = "HeadOps"
ROLE_INSTALL_MGR = "InstallManager"
ROLE_ADS_MGR = "AdsManager"
ROLE_INSTALL_FIELD = "InstallField"
ROLE_ADS_FIELD = "AdsField"
ROLE_VIEWER = "Viewer"
ROLE_EXECUTIVE = "Executive"

ROLE_LABEL = {
    ROLE_EXECUTIVE: "Executive / CEO (Read-only dashboards)",
    ROLE_SUPERADMIN: "Super Admin (All)",
    ROLE_HEAD: "Head of Ops (All)",
    ROLE_INSTALL_MGR: "Installation Manager",
    ROLE_ADS_MGR: "Advertisement Manager",
    ROLE_INSTALL_FIELD: "Field Team (Installation)",
    ROLE_ADS_FIELD: "Field Team (Advertisement)",
    ROLE_VIEWER: "Viewer (Read-only)",
}

DEFAULT_PERMS = {
    ROLE_SUPERADMIN: {"*": {"view": 1, "add": 1, "edit": 1, "delete": 1, "export": 1}},
    ROLE_HEAD: {"*": {"view": 1, "add": 1, "edit": 1, "delete": 0, "export": 1}},
    ROLE_INSTALL_MGR: {SECTION_INSTALL: {"view": 1, "add": 1, "edit": 1, "delete": 0, "export": 1}},
    ROLE_ADS_MGR: {SECTION_ADS: {"view": 1, "add": 1, "edit": 1, "delete": 0, "export": 1}},
    ROLE_INSTALL_FIELD: {SECTION_INSTALL: {"view": 1, "add": 1, "edit": 1, "delete": 0, "export": 0}},
    ROLE_ADS_FIELD: {SECTION_ADS: {"view": 1, "add": 1, "edit": 1, "delete": 0, "export": 0}},
    ROLE_VIEWER: {"*": {"view": 1, "add": 0, "edit": 0, "delete": 0, "export": 0}},
    ROLE_EXECUTIVE: {"*": {"view": 1, "add": 0, "edit": 0, "delete": 0, "export": 1}},
}

LEAD_STATUS = ["New", "Contacted", "Follow-up Required", "Interested", "Installed", "Active", "Rejected/Not Suitable"]
CALL_OUTCOMES = ["Interested", "Follow-up", "Not Reachable", "Rejected"]

DOC_TYPES_INSTALL = [
    "Society Agreement Copy", "Permission Letter", "NOC", "Installation Checklist",
    "Agreement Copy", "Property Photo", "Other"
]

UPLOAD_ROOT = "uploads_docs"
UPLOAD_INSTALL = os.path.join(UPLOAD_ROOT, "installation")
UPLOAD_SIG = os.path.join(UPLOAD_ROOT, "signatures")
os.makedirs(UPLOAD_INSTALL, exist_ok=True)
os.makedirs(UPLOAD_SIG, exist_ok=True)

# Must be the FIRST Streamlit call
st.set_page_config(page_title=APP_TITLE, layout="wide", page_icon="🟧")


# =========================================================
# UI THEME (single CSS block, mobile-friendly)
# =========================================================
st.markdown(
    """
<style>
:root{
  --bg:#ffffff; --surface:#ffffff; --surface2:#f6f8fb; --border:#e6e8ef;
  --text:#0f172a; --muted:#475569; --accent:#0f5b66; --warn:#b45309; --danger:#b91c1c; --ok:#15803d;
}
.block-container{max-width:1560px;padding-top:.65rem;padding-bottom:2rem;}
[data-testid="stAppViewContainer"]{background:var(--bg);}
[data-testid="stHeader"]{background:rgba(255,255,255,.92);border-bottom:1px solid var(--border);}
[data-testid="stSidebar"]{background:var(--surface2);border-right:1px solid var(--border);}
.card{background:var(--surface);border:1px solid var(--border);border-radius:18px;padding:14px;box-shadow:0 8px 24px rgba(15,23,42,.06);}
.card-tight{background:var(--surface);border:1px solid var(--border);border-radius:14px;padding:12px;}
.small{color:var(--muted);font-size:.92rem;}
.section{font-weight:850;font-size:1.05rem;margin:0 0 .25rem 0;}
.kpi{background:#fff;border:1px solid var(--border);border-radius:16px;padding:10px 12px;}
.kpi .label{color:var(--muted);font-size:.85rem;margin-bottom:2px;}
.kpi .val{font-weight:850;font-size:1.25rem;color:var(--text);}
.sticky-wrap{
  position:sticky;top:0;z-index:999;background:rgba(255,255,255,.96);backdrop-filter:blur(6px);
  border-bottom:1px solid var(--border);padding:8px 0 10px 0;margin-bottom:10px;
}
div.stButton>button{width:100%;border-radius:12px;padding:.65rem .9rem;font-weight:650;border:1px solid var(--border);}
div.stButton>button[kind="primary"]{background:var(--accent);color:#fff;border:1px solid rgba(15,91,102,.35);}
hr{border:0;border-top:1px solid var(--border);margin:1rem 0;}
.brandbar{
  display:flex;align-items:center;gap:12px;
  padding:10px 14px;border:1px solid var(--border);
  border-radius:18px;background:#fff;
  box-shadow:0 8px 24px rgba(15,23,42,.06);
  margin-bottom:10px;
}
.brandbar .title{font-weight:900;font-size:1.2rem;color:var(--text);line-height:1;}
.brandbar .sub{color:var(--muted);font-size:.92rem;margin-top:2px;}
.brandbar img{height:44px; width:auto;}
.badge{display:inline-block;padding:5px 10px;border-radius:999px;border:1px solid var(--border);background:#fff;color:var(--muted);font-size:.82rem;margin-right:6px;margin-bottom:6px;}
.badge-strong{border-color:rgba(15,91,102,.25);background:rgba(15,91,102,.06);color:var(--accent);}
@media (max-width: 900px){
  .block-container{padding-left:0.85rem;padding-right:0.85rem;}
  .brandbar img{height:38px;}
}
</style>
""",
    unsafe_allow_html=True,
)


def _img_to_base64(path: str) -> str:
    p = Path(path)
    if not p.exists():
        return ""
    import base64
    return base64.b64encode(p.read_bytes()).decode("utf-8")


logo_b64 = _img_to_base64(LOGO_PATH)
if logo_b64:
    logo_html = f"<img src='data:image/png;base64,{logo_b64}'/>"
else:
    logo_html = "<div style='width:44px;height:44px;border-radius:10px;background:rgba(15,91,102,.08);border:1px solid #e6e8ef;'></div>"

st.markdown(
    f"""
<div class="brandbar">
  {logo_html}
  <div>
    <div class="title">The Adbook AIAMS</div>
    <div class="sub">Inventory • Agreements • WhatsApp • Proposals • Reports</div>
  </div>
</div>
""",
    unsafe_allow_html=True,
)


# =========================================================
# DATABASE (SUPABASE)
# =========================================================
def get_database_url() -> str:
    try:
        if "DATABASE_URL" in st.secrets:
            return str(st.secrets["DATABASE_URL"]).strip()
    except Exception:
        pass
    return os.environ.get("DATABASE_URL", "").strip()


@st.cache_resource(show_spinner=False)
def db_engine():
    db_url = get_database_url()
    if not db_url:
        st.error("DATABASE_URL not found. Add it in Streamlit Secrets or environment variable.")
        st.stop()

    if "postgresql+psycopg://" not in db_url and db_url.startswith("postgres"):
        st.warning("Tip: Use 'postgresql+psycopg://' in DATABASE_URL for best compatibility on Streamlit Cloud.")

    return create_engine(
        db_url,
        pool_pre_ping=True,
        pool_size=3,
        max_overflow=2,
        pool_timeout=30,
    )


def exec_sql(sql: str, params: dict | None = None) -> None:
    try:
        with db_engine().begin() as conn:
            conn.execute(text(sql), params or {})
    except SQLAlchemyError as e:
        st.error("Database error while executing SQL.")
        st.code(str(e))
        st.stop()


def qdf(sql: str, params: dict | None = None) -> pd.DataFrame:
    try:
        with db_engine().connect() as conn:
            return pd.read_sql(text(sql), conn, params=params or {})
    except SQLAlchemyError as e:
        st.error("Database error while reading data.")
        st.code(str(e))
        st.stop()


# =========================================================
# MIGRATIONS + SEED (RUN ONCE PER SERVER)
# =========================================================
@st.cache_resource(show_spinner=False)
def init_db_once():
    # tables
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
    )""")

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
    )""")

    exec_sql("""
    CREATE TABLE IF NOT EXISTS audit_logs(
      log_id TEXT PRIMARY KEY,
      username TEXT,
      action_type TEXT,
      details TEXT,
      created_at TIMESTAMP DEFAULT NOW()
    )""")

    exec_sql("""
    CREATE TABLE IF NOT EXISTS property_codes(
      property_id TEXT PRIMARY KEY,
      property_code TEXT UNIQUE,
      district TEXT,
      city TEXT,
      property_name TEXT,
      created_at TIMESTAMP DEFAULT NOW()
    )""")

    exec_sql("""
    CREATE TABLE IF NOT EXISTS lead_updates(
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
    )""")

    exec_sql("""
    CREATE TABLE IF NOT EXISTS inventory_sites(
      property_id TEXT PRIMARY KEY,
      property_code TEXT,
      district TEXT,
      city TEXT,
      property_name TEXT,
      property_address TEXT,
      latitude DOUBLE PRECISION,
      longitude DOUBLE PRECISION,
      date_of_contract TEXT,
      contract_period TEXT,
      screen_installed_date TEXT,
      contract_terms TEXT,
      site_rating INTEGER,
      chairman_name TEXT,
      contact_person TEXT,
      contact_details TEXT,
      no_screens_installed INTEGER DEFAULT 0,
      agreed_rent_pm DOUBLE PRECISION,
      notes TEXT,
      last_updated TIMESTAMP DEFAULT NOW()
    )""")

    exec_sql("""
    CREATE TABLE IF NOT EXISTS screens(
      screen_id TEXT PRIMARY KEY,
      property_id TEXT NOT NULL,
      screen_location TEXT,
      installed_date TEXT,
      installed_by TEXT,
      last_service_date TEXT,
      next_service_due TEXT,
      is_active INTEGER DEFAULT 1,
      last_updated TIMESTAMP DEFAULT NOW()
    )""")

    exec_sql("""
    CREATE TABLE IF NOT EXISTS documents_install(
      doc_id TEXT PRIMARY KEY,
      property_id TEXT,
      doc_type TEXT,
      filename TEXT,
      issue_date TEXT,
      expiry_date TEXT,
      uploaded_by TEXT,
      uploaded_at TIMESTAMP DEFAULT NOW()
    )""")

    exec_sql("""
    CREATE TABLE IF NOT EXISTS proposals(
      proposal_id TEXT PRIMARY KEY,
      section TEXT NOT NULL,
      property_id TEXT,
      proposal_no INTEGER NOT NULL,
      created_by TEXT,
      created_at TIMESTAMP DEFAULT NOW(),
      pdf_filename TEXT,
      status TEXT
    )""")

    exec_sql("""
    CREATE TABLE IF NOT EXISTS whatsapp_logs(
      log_id TEXT PRIMARY KEY,
      lead_hash TEXT,
      username TEXT,
      action_status TEXT,
      created_at TIMESTAMP DEFAULT NOW()
    )""")

    exec_sql("""
    CREATE TABLE IF NOT EXISTS company_settings(
      settings_id TEXT PRIMARY KEY,
      gst_no TEXT,
      bank_details TEXT,
      whatsapp_limit_per_hour INTEGER DEFAULT 50,
      updated_at TIMESTAMP DEFAULT NOW()
    )""")

    exec_sql("""
    CREATE TABLE IF NOT EXISTS user_profiles(
      username TEXT PRIMARY KEY,
      signature_filename TEXT,
      designation TEXT,
      mobile TEXT,
      email TEXT,
      updated_at TIMESTAMP DEFAULT NOW()
    )""")


    exec_sql("""
    CREATE TABLE IF NOT EXISTS manual_leads(
      lead_id TEXT PRIMARY KEY,
      section TEXT NOT NULL,
      district TEXT,
      city TEXT,
      property_name TEXT,
      property_address TEXT,
      promoter_name TEXT,
      promoter_mobile TEXT,
      promoter_email TEXT,
      property_type TEXT,
      property_status TEXT,
      notes TEXT,
      created_by TEXT,
      created_at TIMESTAMP DEFAULT NOW(),
      updated_at TIMESTAMP DEFAULT NOW()
    )""")

    exec_sql("""
    CREATE TABLE IF NOT EXISTS agreements(
      agreement_id TEXT PRIMARY KEY,
      section TEXT NOT NULL,
      property_id TEXT,
      property_code TEXT,
      party_name TEXT,
      start_date TEXT,
      end_date TEXT,
      renewal_type TEXT,
      rent_pm DOUBLE PRECISION,
      billing_cycle TEXT,
      status TEXT,
      notes TEXT,
      created_by TEXT,
      created_at TIMESTAMP DEFAULT NOW(),
      updated_at TIMESTAMP DEFAULT NOW()
    )""")

    exec_sql("""
    CREATE TABLE IF NOT EXISTS payments(
      payment_id TEXT PRIMARY KEY,
      agreement_id TEXT,
      section TEXT NOT NULL,
      property_id TEXT,
      due_date TEXT,
      amount DOUBLE PRECISION,
      status TEXT,
      paid_date TEXT,
      payment_mode TEXT,
      reference_no TEXT,
      notes TEXT,
      created_by TEXT,
      created_at TIMESTAMP DEFAULT NOW()
    )""")

    exec_sql("""
    CREATE TABLE IF NOT EXISTS documents_vault(
      doc_id TEXT PRIMARY KEY,
      section TEXT NOT NULL,
      property_id TEXT,
      doc_type TEXT,
      filename TEXT,
      storage_path TEXT,
      issue_date TEXT,
      expiry_date TEXT,
      uploaded_by TEXT,
      uploaded_at TIMESTAMP DEFAULT NOW()
    )""")

    exec_sql("""
    CREATE TABLE IF NOT EXISTS ad_inventory(
      ad_id TEXT PRIMARY KEY,
      section TEXT NOT NULL,
      property_id TEXT,
      screen_id TEXT,
      slot_name TEXT,
      start_date TEXT,
      end_date TEXT,
      rate DOUBLE PRECISION,
      status TEXT,
      client_name TEXT,
      notes TEXT,
      created_by TEXT,
      created_at TIMESTAMP DEFAULT NOW(),
      updated_at TIMESTAMP DEFAULT NOW()
    )""")

    # helpful indexes (safe)
    exec_sql("CREATE INDEX IF NOT EXISTS idx_lead_updates_section_updated ON lead_updates(section, last_updated DESC)")
    exec_sql("CREATE INDEX IF NOT EXISTS idx_inventory_last_updated ON inventory_sites(last_updated DESC)")
    exec_sql("CREATE INDEX IF NOT EXISTS idx_screens_property ON screens(property_id)")
    exec_sql("CREATE INDEX IF NOT EXISTS idx_docs_property ON documents_install(property_id)")
    exec_sql("CREATE INDEX IF NOT EXISTS idx_wa_created ON whatsapp_logs(created_at DESC)")
    exec_sql("CREATE INDEX IF NOT EXISTS idx_manual_leads_section ON manual_leads(section, created_at DESC)")
    exec_sql("CREATE INDEX IF NOT EXISTS idx_agreements_section ON agreements(section, status)")
    exec_sql("CREATE INDEX IF NOT EXISTS idx_payments_due ON payments(section, due_date)")
    exec_sql("CREATE INDEX IF NOT EXISTS idx_docs_vault_prop ON documents_vault(property_id)")
    exec_sql("CREATE INDEX IF NOT EXISTS idx_adinv_prop ON ad_inventory(property_id)")

    # seed permissions if empty
    c = int(qdf("SELECT COUNT(*) AS c FROM permissions").iloc[0]["c"] or 0)
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



    # indexes for faster searches (best-effort; safe if already exists)
    exec_sql("CREATE INDEX IF NOT EXISTS idx_inventory_search ON inventory_sites (property_code, district, city, property_name)")
    exec_sql("CREATE INDEX IF NOT EXISTS idx_screens_pid ON screens (property_id)")
    exec_sql("CREATE INDEX IF NOT EXISTS idx_agreements_pid ON agreements (property_id)")
    exec_sql("CREATE INDEX IF NOT EXISTS idx_payments_agreement ON payments (agreement_id)")
    exec_sql("CREATE INDEX IF NOT EXISTS idx_docs_property ON documents_vault (property_id)")
    exec_sql("CREATE INDEX IF NOT EXISTS idx_adinv_property ON ad_inventory (property_id)")

    return True



init_db_once()


# =========================================================
# AUTH
# =========================================================
def pbkdf2_hash(password: str, salt: str | None = None) -> str:
    salt = salt or uuid.uuid4().hex
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 120_000)
    return f"pbkdf2_sha256${salt}${dk.hex()}"


def pbkdf2_verify(password: str, stored: str) -> bool:
    try:
        if stored.startswith("plain$"):
            return password == stored.split("$", 1)[1]
        alg, salt, hexhash = stored.split("$", 2)
        if alg != "pbkdf2_sha256":
            return False
        return pbkdf2_hash(password, salt).split("$", 2)[2] == hexhash
    except Exception:
        return False


def audit(user: str, action: str, details: str = ""):
    exec_sql(
        "INSERT INTO audit_logs(log_id,username,action_type,details) VALUES(:id,:u,:a,:d)",
        {"id": str(uuid.uuid4()), "u": user, "a": action, "d": details},
    )


def get_user(username: str):
    df = qdf("SELECT * FROM users WHERE username=:u", {"u": username})
    return df.iloc[0].to_dict() if len(df) else None


def set_last_login(username: str):
    exec_sql("UPDATE users SET last_login_at=NOW(), updated_at=NOW() WHERE username=:u", {"u": username})


@st.cache_data(show_spinner=False, ttl=120)
def load_permissions():
    return qdf("SELECT role, section, can_view, can_add, can_edit, can_delete, can_export FROM permissions")


def can(section: str, action: str, role: str) -> bool:
    if role == ROLE_SUPERADMIN:
        return True
    perms = load_permissions()
    sub = perms[(perms["role"] == role) & (perms["section"].isin([section, "*"]))]
    if len(sub) == 0:
        return action == "view"
    spec = sub[sub["section"] == section]
    row = (spec.iloc[0] if len(spec) else sub.iloc[0]).to_dict()
    return bool(row.get(f"can_{action}", 0))


def page_title(title: str, subtitle: str):
    st.markdown(
        f"<div class='card'><div class='section'>{title}</div><div class='small'>{subtitle}</div></div>",
        unsafe_allow_html=True,
    )


def kpi(label, value):
    st.markdown(
        f"<div class='kpi'><div class='label'>{label}</div><div class='val'>{value}</div></div>",
        unsafe_allow_html=True,
    )


def bootstrap_if_no_users():
    c = int(qdf("SELECT COUNT(*) AS c FROM users").iloc[0]["c"] or 0)
    if c > 0:
        return

    st.warning("No users found. Create the first SuperAdmin below (one-time).")
    with st.form("bootstrap_admin"):
        u = st.text_input("Admin Username", value="admin")
        p = st.text_input("Admin Password", type="password")
        mode = st.selectbox("Password mode", ["Secure (recommended)", "Simple (plain$)"], index=0)
        ok = st.form_submit_button("Create SuperAdmin", type="primary")
    if ok:
        if not u.strip() or not p:
            st.error("Username and password required.")
            st.stop()
        ph = pbkdf2_hash(p) if mode.startswith("Secure") else "plain$" + p
        exec_sql(
            """INSERT INTO users(username,password_hash,role,section_scope,is_active)
               VALUES(:u,:p,:r,'Both',1)""",
            {"u": u.strip(), "p": ph, "r": ROLE_SUPERADMIN},
        )
        audit(u.strip(), "BOOTSTRAP_ADMIN", "created first SuperAdmin")
        st.success("SuperAdmin created. Please refresh and login.")
        st.stop()


bootstrap_if_no_users()


def require_auth():
    if "auth" in st.session_state:
        return
    with st.sidebar:
        st.markdown("### 🔐 Login")
        u = st.text_input("Username").strip()
        p = st.text_input("Password", type="password")
        if st.button("Login", type="primary"):
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
SCOPE = AUTH.get("scope", SCOPE_BOTH)


# =========================================================
# DATA HELPERS (FAST + CACHED PREP)
# =========================================================

def df_to_csv_bytes(df: pd.DataFrame) -> bytes:
    return df.to_csv(index=False).encode("utf-8")

def ilike_clause(columns: list[str], param_name: str = "q") -> str:
    parts = [f"{c} ILIKE :{param_name}" for c in columns]
    return "(" + " OR ".join(parts) + ")"

def sql_q(term: str) -> str:
    term = (term or "").strip()
    return f"%{term}%" if term else "%"

def global_search(term: str) -> dict[str, pd.DataFrame]:
    t = (term or "").strip()
    if not t:
        return {}
    q = sql_q(t)
    out: dict[str, pd.DataFrame] = {}
    out["Inventory (Sites)"] = qdf(
        f"""SELECT property_id, property_code, district, city, property_name, property_address,
                    contact_person, contact_details, agreed_rent_pm, no_screens_installed, last_updated
               FROM inventory_sites
              WHERE {ilike_clause(['property_code','district','city','property_name','property_address','contact_person','contact_details'], 'q')}
              ORDER BY last_updated DESC
              LIMIT 200""",
        {"q": q},
    )
    out["Screens"] = qdf(
        f"""SELECT s.screen_id, s.property_id, i.property_name, i.city, s.screen_location,
                    s.installed_date, s.last_service_date, s.next_service_due, s.is_active, s.last_updated
               FROM screens s
               LEFT JOIN inventory_sites i ON i.property_id = s.property_id
              WHERE {ilike_clause(['s.screen_id','s.property_id','i.property_name','i.city','s.screen_location','s.installed_by'], 'q')}
              ORDER BY s.last_updated DESC
              LIMIT 200""",
        {"q": q},
    )
    out["Agreements"] = qdf(
        f"""SELECT agreement_id, property_id, party_name, property_code, start_date, end_date, rent_pm, billing_cycle,
                    status, updated_at
               FROM agreements
              WHERE {ilike_clause(['agreement_id','property_id','party_name','property_code','status','billing_cycle','notes'], 'q')}
              ORDER BY updated_at DESC
              LIMIT 200""",
        {"q": q},
    )
    out["Billing & Reminders"] = qdf(
        f"""SELECT payment_id, agreement_id, amount, due_date, status, paid_date, updated_at
               FROM payments
              WHERE {ilike_clause(['payment_id','agreement_id','status','notes'], 'q')}
              ORDER BY updated_at DESC
              LIMIT 200""",
        {"q": q},
    )
    out["Documents Vault"] = qdf(
        f"""SELECT doc_id, property_id, doc_type, filename, issue_date, expiry_date, uploaded_by, uploaded_at
               FROM documents_vault
              WHERE {ilike_clause(['doc_id','property_id','doc_type','filename','uploaded_by'], 'q')}
              ORDER BY uploaded_at DESC
              LIMIT 200""",
        {"q": q},
    )
    out["Ad Sales Inventory"] = qdf(
        f"""SELECT booking_id, property_id, client_name, screen_id, start_date, end_date, rate_pm, status, updated_at
               FROM ad_inventory
              WHERE {ilike_clause(['booking_id','property_id','client_name','screen_id','status','notes'], 'q')}
              ORDER BY updated_at DESC
              LIMIT 200""",
        {"q": q},
    )
    return out

def normalize_mobile_series(s: pd.Series) -> pd.Series:
    s = s.fillna("").astype(str)
    s = s.str.replace(r"[^0-9+]", "", regex=True).str.replace("+91", "", regex=False)
    s = s.str.replace(r"\D", "", regex=True)
    # vectorized last-10
    lens = s.str.len()
    s = s.where(lens <= 10, s.str[-10:])
    return s


@st.cache_data(show_spinner=False)
def _read_csv_bytes(file_bytes: bytes) -> pd.DataFrame:
    encodings_to_try = ["utf-8-sig", "utf-8", "cp1252", "latin1"]
    for enc in encodings_to_try:
        try:
            return pd.read_csv(io.BytesIO(file_bytes), encoding=enc, dtype=str, low_memory=False)
        except UnicodeDecodeError:
            continue
    return pd.read_csv(
        io.BytesIO(file_bytes),
        encoding="latin1",
        dtype=str,
        low_memory=False,
        engine="python",
        on_bad_lines="skip",
    )


@st.cache_data(show_spinner=False)
def _read_excel_sheet(file_bytes: bytes, sheet_name: str) -> pd.DataFrame:
    return pd.read_excel(io.BytesIO(file_bytes), sheet_name=sheet_name, dtype=str, engine="openpyxl")


def _letters2(x) -> str:
    s = "" if x is None else str(x)
    s = s.upper()
    s = re.sub(r"[^A-Za-z]", "", s)
    return (s + "XX")[:2]


def _local_file_signature(path: str) -> str:
    p = Path(path)
    if not p.exists():
        return ""
    stat = p.stat()
    return f"{p.name}|{stat.st_size}|{int(stat.st_mtime)}"


@st.cache_data(show_spinner=False)
def prepare_leads_from_bytes(file_bytes: bytes, filename: str, excel_sheet: str | None) -> pd.DataFrame:
    # load
    if filename.endswith(".csv"):
        df = _read_csv_bytes(file_bytes)
    else:
        if not excel_sheet:
            # should not happen; safety
            excel_sheet = "Sheet1"
        df = _read_excel_sheet(file_bytes, excel_sheet)

    df.columns = [str(c).strip() for c in df.columns]
    if "District Type" in df.columns and "City" not in df.columns:
        df = df.rename(columns={"District Type": "City"})

    required_cols = [
        "District", "City", "Property Name", "Property Address",
        "Promoter Mobile Number", "Promoter Email", "Promoter / Developer Name"
    ]
    for col in required_cols:
        if col not in df.columns:
            df[col] = ""

    # clean strings (vectorized)
    for c in required_cols:
        df[c] = df[c].fillna("").astype(str).str.strip()

    df["__mobile_norm"] = normalize_mobile_series(df["Promoter Mobile Number"])

    # FAST stable hash without python loop:
    # use uint64 -> decimal string (unique enough for this app)
    hash_cols = pd.DataFrame({
        "pn": df["Property Name"].str.lower(),
        "pa": df["Property Address"].str.lower(),
        "d": df["District"].str.lower(),
        "c": df["City"].str.lower(),
        "m": df["__mobile_norm"],
        "e": df["Promoter Email"].str.lower(),
    })
    h64 = pd.util.hash_pandas_object(hash_cols, index=False).astype("uint64")
    df["__hash"] = h64.astype(str)

    # single search index column
    df["__search"] = (
        df["Property Name"] + " | " +
        df["Property Address"] + " | " +
        df["Promoter / Developer Name"] + " | " +
        df["Promoter Email"] + " | " +
        df["Promoter Mobile Number"] + " | " +
        df["District"] + " | " +
        df["City"]
    ).str.lower()

    return df


def read_leads_file(upload=None) -> tuple[pd.DataFrame, str]:
    """
    Returns (prepared_df, version_key)
    version_key changes only when underlying file changes.
    """
    if upload is None:
        if not os.path.exists(DATA_FILE):
            st.error(f"Missing {DATA_FILE}. Upload a file OR add {DATA_FILE} next to app.py.")
            st.stop()
        sig = _local_file_signature(DATA_FILE)
        file_bytes = Path(DATA_FILE).read_bytes()
        filename = DATA_FILE.lower()
        excel_sheet = None
        version_key = f"local:{sig}"
    else:
        file_bytes = upload.getvalue()
        filename = upload.name.lower()
        # version based on content hash (fast, stable)
        content_hash = hashlib.sha256(file_bytes).hexdigest()[:16]
        version_key = f"upload:{filename}:{content_hash}"
        excel_sheet = None

        if filename.endswith(".xlsx") or filename.endswith(".xls"):
            xl = pd.ExcelFile(io.BytesIO(file_bytes))
            excel_sheet = st.selectbox("Select sheet", xl.sheet_names, key="sheet_picker")

    df = prepare_leads_from_bytes(file_bytes, filename, excel_sheet)
    return df, version_key


# =========================================================
# PROPERTY CODES (READ CACHED, INSERT ONLY WHEN MISSING)
# =========================================================
@st.cache_data(show_spinner=False, ttl=120)
def get_property_codes_df() -> pd.DataFrame:
    return qdf("SELECT property_id, property_code, district, city, property_name FROM property_codes")


def ensure_property_codes(leads_df: pd.DataFrame, batch_size: int = 700) -> pd.DataFrame:
    needed = leads_df[["__hash", "District", "City", "Property Name"]].drop_duplicates().copy()
    needed.columns = ["property_id", "district", "city", "property_name"]

    existing = get_property_codes_df()
    existing_ids = set(existing["property_id"].astype("string").tolist()) if len(existing) else set()

    missing = needed[~needed["property_id"].astype("string").isin(existing_ids)]
    if len(missing) == 0:
        return existing

    used_by_prefix = {}
    if len(existing):
        pc = existing["property_code"].astype("string").fillna("")
        pref = pc.str.slice(0, 4)
        num = pd.to_numeric(pc.str.slice(4, 7), errors="coerce")
        ok = pref.str.match(r"^[A-Z]{4}$", na=False) & num.notna()
        for p, n in zip(pref[ok], num[ok].astype(int)):
            used_by_prefix.setdefault(p, set()).add(int(n))

    next_num = {}
    def next_for(pref: str) -> int:
        if pref not in next_num:
            next_num[pref] = (max(used_by_prefix.get(pref, {0})) + 1) if used_by_prefix.get(pref) else 1
        return next_num[pref]

    inserts = []
    for r in missing.to_dict("records"):
        district = r.get("district", "") or ""
        city = r.get("city", "") or ""
        pname = r.get("property_name", "") or ""
        pid = str(r["property_id"])
        pref = _letters2(district) + _letters2(city)

        n = next_for(pref)
        while n in used_by_prefix.get(pref, set()):
            n += 1
        code = f"{pref}{n:03d}"
        used_by_prefix.setdefault(pref, set()).add(n)
        next_num[pref] = n + 1

        inserts.append({"pid": pid, "code": code, "district": district, "city": city, "pname": pname})

    if inserts:
        sql = text("""
            INSERT INTO property_codes(property_id, property_code, district, city, property_name)
            VALUES(:pid, :code, :district, :city, :pname)
            ON CONFLICT (property_id) DO NOTHING
        """)
        for i in range(0, len(inserts), batch_size):
            batch = inserts[i:i+batch_size]
            with db_engine().begin() as conn:
                conn.execute(sql, batch)

        # invalidate cache only when we inserted
        get_property_codes_df.clear()

    return get_property_codes_df()


def property_display_map(code_df: pd.DataFrame, leads_df: pd.DataFrame) -> dict:
    # vectorized label building via merge (faster than python loop)
    mini = leads_df.drop_duplicates("__hash")[["__hash", "Property Name", "City"]].copy()
    mini = mini.rename(columns={"__hash": "property_id"})
    merged = code_df.merge(mini, on="property_id", how="left")

    pn = merged["Property Name"].fillna("").astype(str).str.slice(0, 45)
    ct = merged["City"].fillna("").astype(str)
    code = merged["property_code"].fillna("").astype(str)
    pid = merged["property_id"].fillna("").astype(str)

    label = code + " — " + pn + " — " + ct
    label = label.where(pn.ne("") | ct.ne(""), code + " — " + pid.str.slice(0, 6))

    return dict(zip(pid.tolist(), label.tolist()))


# =========================================================
# LEAD UPDATES (cached)
# =========================================================
@st.cache_data(show_spinner=False, ttl=30)
def list_lead_updates(section: str) -> pd.DataFrame:
    return qdf("SELECT * FROM lead_updates WHERE section=:s", {"s": section})


def upsert_lead_update(section, record_hash, status, assigned_to, lead_source, notes, follow_up, last_call_outcome=None):
    exec_sql(
        """
        INSERT INTO lead_updates(record_hash,section,status,assigned_to,lead_source,notes,follow_up,last_call_outcome,last_call_at,last_updated)
        VALUES(:h,:s,:st,:as,:src,:n,:fu,:out,CASE WHEN :out IS NULL THEN NULL ELSE NOW() END,NOW())
        ON CONFLICT(record_hash, section) DO UPDATE SET
          status=EXCLUDED.status,
          assigned_to=EXCLUDED.assigned_to,
          lead_source=EXCLUDED.lead_source,
          notes=EXCLUDED.notes,
          follow_up=EXCLUDED.follow_up,
          last_call_outcome=COALESCE(EXCLUDED.last_call_outcome, lead_updates.last_call_outcome),
          last_call_at=CASE WHEN EXCLUDED.last_call_outcome IS NULL THEN lead_updates.last_call_at ELSE NOW() END,
          last_updated=NOW()
        """,
        {"h": record_hash, "s": section, "st": status, "as": assigned_to, "src": lead_source, "n": notes, "fu": follow_up, "out": last_call_outcome},
    )
    list_lead_updates.clear()


# =========================================================
# SETTINGS / PROFILES
# =========================================================
@st.cache_data(show_spinner=False, ttl=60)
def get_company_settings():
    df = qdf("SELECT * FROM company_settings LIMIT 1")
    if len(df) == 0:
        sid = str(uuid.uuid4())
        exec_sql("INSERT INTO company_settings(settings_id, gst_no, bank_details, whatsapp_limit_per_hour) VALUES(:i,'','',50)", {"i": sid})
        df = qdf("SELECT * FROM company_settings LIMIT 1")
    return df.iloc[0].to_dict()


def upsert_company_settings(gst_no: str, bank_details: str, limit_per_hour: int):
    cur = get_company_settings()
    exec_sql(
        """
        UPDATE company_settings
        SET gst_no=:g, bank_details=:b, whatsapp_limit_per_hour=:l, updated_at=NOW()
        WHERE settings_id=:id
        """,
        {"g": gst_no, "b": bank_details, "l": int(limit_per_hour), "id": cur["settings_id"]},
    )
    get_company_settings.clear()


@st.cache_data(show_spinner=False, ttl=120)
def get_user_profile(username: str):
    df = qdf("SELECT * FROM user_profiles WHERE username=:u", {"u": username})
    if len(df) == 0:
        exec_sql("INSERT INTO user_profiles(username, signature_filename, designation, mobile, email) VALUES(:u,'','','','')", {"u": username})
        df = qdf("SELECT * FROM user_profiles WHERE username=:u", {"u": username})
    return df.iloc[0].to_dict()


def update_user_signature(username: str, filename: str):
    exec_sql("UPDATE user_profiles SET signature_filename=:f, updated_at=NOW() WHERE username=:u", {"u": username, "f": filename})
    get_user_profile.clear()


# =========================================================
# PDF PROPOSAL (Reportlab)
# =========================================================
def next_proposal_no():
    df = qdf("SELECT MAX(proposal_no) AS m FROM proposals")
    m = df.iloc[0]["m"]
    return int(m or 0) + 1


def make_proposal_pdf_bytes(section: str, data: dict, settings: dict, signer: dict, validity_days: int = 15) -> bytes:
    buffer = BytesIO()
    c = canvas.Canvas(buffer, pagesize=A4)
    width, height = A4

    left = 40
    y = height - 40

    def line(txt="", size=11, bold=False, gap=16):
        nonlocal y
        if y < 60:
            c.showPage()
            y = height - 40
        c.setFont("Helvetica-Bold" if bold else "Helvetica", size)
        c.drawString(left, y, str(txt)[:140])
        y -= gap

    def hr(gap=14):
        nonlocal y
        c.line(left, y, width - left, y)
        y -= gap

    line("The Adbook Outdoor", 16, True, 22)
    line(WEBSITE_URL, 10, False, 14)

    pno = data.get("proposal_no", "")
    today = date.today().strftime("%d-%b-%Y")
    valid_till = (date.today() + timedelta(days=validity_days)).strftime("%d-%b-%Y")

    c.setFont("Helvetica", 10)
    c.drawRightString(width - left, height - 40, f"Proposal No: {pno}")
    c.drawRightString(width - left, height - 54, f"Date: {today}")
    c.drawRightString(width - left, height - 68, f"Valid till: {valid_till}")

    hr()
    title = "Installation Proposal" if section == SECTION_INSTALL else "Advertisement Proposal"
    line(title, 13, True, 18)

    line("Property Details", 11, True, 16)
    line(f"Property: {data.get('property_name','')}", 11, False, 14)
    line(f"Address: {data.get('property_address','')}", 11, False, 14)
    line(f"District/City: {data.get('district','')} / {data.get('city','')}", 11, False, 14)
    line(f"Contact: {data.get('contact_person','')} | {data.get('contact_phone','')} | {data.get('contact_email','')}", 11, False, 16)

    hr()
    line("Scope", 11, True, 16)
    for s in (data.get("scope_points", []) or ["Scope to be finalized."]):
        line(f"• {s}", 11, False, 14)

    hr()
    line("Pricing", 11, True, 16)
    pricing_rows = data.get("pricing_rows", []) or []
    if not pricing_rows:
        line("• Pricing to be finalized after discussion.", 11, False, 14)
    else:
        for pr in pricing_rows:
            line(f"• {pr.get('item','')} | INR {pr.get('amount','')} | {pr.get('notes','')}", 11, False, 14)

    hr()
    line("Payment Terms", 11, True, 16)
    for p in (data.get("payment_terms", []) or ["Payment terms to be finalized."]):
        line(f"• {p}", 11, False, 14)

    hr()
    line("GST", 11, True, 16)
    line(settings.get("gst_no", "") or "Applicable as per rules.", 11, False, 16)

    line("Bank Details", 11, True, 16)
    bank = (settings.get("bank_details", "") or "").strip()
    if not bank:
        line("Will be shared on request.", 11, False, 14)
    else:
        for bl in bank.splitlines():
            line(bl, 11, False, 14)

    hr()
    line("For The Adbook Outdoor", 11, True, 16)
    line(f"Name: {signer.get('username','')}", 11, False, 14)
    line(f"Designation: {signer.get('designation','')}", 11, False, 14)

    c.setFont("Helvetica", 9)
    c.drawString(left, 30, "This proposal is system-generated by AIAMS (cloud-safe PDF).")
    c.save()
    return buffer.getvalue()


def save_proposal_pdf(section: str, property_id: str, pdf_bytes: bytes, created_by: str) -> dict:
    pno = next_proposal_no()
    fname = f"proposal_{section.lower()}_{pno}_{uuid.uuid4().hex}.pdf"
    path = os.path.join(UPLOAD_INSTALL, fname)
    with open(path, "wb") as f:
        f.write(pdf_bytes)

    exec_sql(
        """
        INSERT INTO proposals(proposal_id, section, property_id, proposal_no, created_by, pdf_filename, status)
        VALUES(:id,:sec,:pid,:pno,:by,:fn,'Generated')
        """,
        {"id": str(uuid.uuid4()), "sec": section, "pid": property_id, "pno": int(pno), "by": created_by, "fn": fname},
    )
    return {"proposal_no": pno, "filename": fname, "path": path}


# =========================================================
# SIDEBAR NAV + USER HELP
# =========================================================
with st.sidebar:
    if Path(LOGO_PATH).exists():
        st.image(LOGO_PATH, use_container_width=True)
    st.markdown("### The Adbook AIAMS")
    st.caption("Outdoor Media Operations System")
    st.markdown("---")

    st.markdown("**Quick Instructions**")
    st.caption("• Use Home for fast search\n• Use Leads to update status\n• Use Inventory/Screens/Documents for Installation\n• Use WhatsApp for click-to-chat")
    st.markdown("---")

    st.markdown("### AIAMS")
    st.markdown(f"**User:** {USER}")
    st.markdown(f"**Role:** {ROLE_LABEL.get(ROLE, ROLE)}")
    st.markdown("---")

    data_mode = st.radio("Data Source", ["Bundled (CSV)", "Upload Excel/CSV"], index=0)
    upload = None
    if data_mode == "Upload Excel/CSV":
        upload = st.file_uploader("Upload file", type=["csv", "xlsx", "xls"])
        if not upload:
            st.stop()

    allowed_sections = [SECTION_INSTALL, SECTION_ADS] if SCOPE == SCOPE_BOTH else [SCOPE]
    SECTION = st.radio("Module", allowed_sections, horizontal=True)

    MENU_INSTALL = ["🏠 Home", "🧩 Leads Pipeline", "🗂 Inventory (Sites)", "🖥 Screens", "🛠 Service Center", "📢 Ad Sales Inventory", "📝 Agreements", "💰 Billing & Reminders", "📄 Documents Vault", "🗺 Map View", "📃 Proposals", "💬 WhatsApp", "📊 Reports"]
    MENU_ADS = ["🏠 Home", "🧩 Leads Pipeline", "📢 Ad Sales Inventory", "📝 Agreements", "💰 Billing & Reminders", "💬 WhatsApp", "📊 Reports"]
    menu = MENU_INSTALL if SECTION == SECTION_INSTALL else MENU_ADS
    if ROLE == ROLE_SUPERADMIN:
        menu = menu + ["Admin Panel"]

    
st.markdown("### 🔎 Global Search")
gq = st.text_input("Search across modules", key="global_search_term", placeholder="Try: city, property, client, agreement, screen…")
st.markdown("---")

PAGE = st.selectbox("Page", menu)

# Normalize to internal page keys (strip emoji/prefix)
PAGE_KEY = re.sub(r"^[^A-Za-z0-9]+\\s*", "", PAGE).strip()




# =========================================================
# LOAD LEADS (CACHED PREP) + CODES ONLY WHEN FILE CHANGES
# =========================================================
leads_df, leads_version = read_leads_file(upload)

# If we already processed codes for this same leads file, reuse from session
if st.session_state.get("leads_version") != leads_version:
    st.session_state["leads_version"] = leads_version
    st.session_state.pop("codes_df", None)
    st.session_state.pop("disp_map", None)
    st.session_state.pop("pid_to_code", None)

if "codes_df" not in st.session_state:
    codes_df = ensure_property_codes(leads_df)
    st.session_state["codes_df"] = codes_df
    st.session_state["disp_map"] = property_display_map(codes_df, leads_df)
    st.session_state["pid_to_code"] = dict(zip(codes_df["property_id"].astype("string"), codes_df["property_code"].astype("string")))

codes_df = st.session_state["codes_df"]
disp_map = st.session_state["disp_map"]
pid_to_code = st.session_state["pid_to_code"]

# Lead updates (cached)
upd = list_lead_updates(SECTION)
leads_df = leads_df.merge(upd, left_on="__hash", right_on="record_hash", how="left")

for c, default in [("status", "New"), ("assigned_to", ""), ("lead_source", "Cold Call"), ("notes", ""), ("follow_up", "")]:
    leads_df[c] = leads_df[c].fillna(default)

# field/viewer: only own assigned
if ROLE in [ROLE_INSTALL_FIELD, ROLE_ADS_FIELD, ROLE_VIEWER]:
    leads_df = leads_df[leads_df["assigned_to"].astype("string") == USER]

# KPI sticky header
st.markdown("<div class='sticky-wrap'>", unsafe_allow_html=True)
c1, c2, c3, c4 = st.columns(4)
with c1:
    kpi("Leads", f"{len(leads_df):,}")
with c2:
    kpi("New", f"{int((leads_df['status'] == 'New').sum()):,}")
with c3:
    kpi("Follow-up", f"{int((leads_df['status'] == 'Follow-up Required').sum()):,}")
with c4:
    kpi("Interested", f"{int((leads_df['status'] == 'Interested').sum()):,}")
st.markdown("</div>", unsafe_allow_html=True)


# =========================================================
# UTILS
# =========================================================

def google_maps_url(property_name: str, address: str) -> str:
    q = f"{property_name} {address}".strip()
    return "https://www.google.com/maps/search/?api=1&query=" + quote_plus(q)

def tel_url(mobile: str) -> str:
    m = re.sub(r"[^0-9+]", "", str(mobile or ""))
    return f"tel:{m}"

def mailto_url(email: str, subject: str = "", body: str = "") -> str:
    email = str(email or "").strip()
    return f"mailto:{email}?subject={quote_plus(subject)}&body={quote_plus(body)}"

def normalize_mobile(x: str) -> str:
    x = re.sub(r"[^0-9+]", "", str(x or ""))
    x = x.replace("+91", "")
    if x.startswith("0") and len(x) > 10:
        x = x.lstrip("0")
    return x

def make_hash(*parts: str) -> str:
    s = "|".join([str(p or "").strip().lower() for p in parts])
    return hashlib.sha1(s.encode("utf-8")).hexdigest()

def whatsapp_url(mobile, message):
    m = str(mobile or "")
    m = re.sub(r"[^0-9]", "", m)
    if len(m) > 10:
        m = m[-10:]
    if not m:
        return "#"
    return f"https://wa.me/91{m}?text={quote_plus(message)}"


def safe_df_cols(df: pd.DataFrame, cols: list[str]) -> pd.DataFrame:
    out = df.copy()
    for c in cols:
        if c not in out.columns:
            out[c] = ""
    return out


# =========================================================
# PAGES
# =========================================================
if PAGE_KEY == "Home":
    page_title("🏠 Home (Fast Search)", f"{SECTION}: Search properties quickly (optimized).")

gq = st.session_state.get("global_search_term", "").strip()
if gq:
    st.markdown("### 🔎 Global Search Results")
    res = global_search(gq)
    any_hit = False
    for mod, df in res.items():
        if df is None or len(df) == 0:
            continue
        any_hit = True
        with st.expander(f"{mod} — {len(df)} results", expanded=False):
            st.dataframe(df, use_container_width=True, height=280)
            if can(SECTION, "export", ROLE):
                st.download_button(f"⬇ Export {mod} (CSV)", data=df_to_csv_bytes(df), file_name=f"{mod.replace(' ','_').lower()}_search.csv", mime="text/csv")
    if not any_hit:
        st.info("No results found in database modules for this search.")
    st.markdown("---")

    q = st.text_input("Search (Property / Promoter / Phone / Email)", placeholder="Type and press Enter…")
    df = leads_df

    if q.strip():
        s = q.strip().lower()
        df = df[df["__search"].str.contains(re.escape(s), na=False)]

    st.markdown(f"<span class='badge badge-strong'>Matches: {len(df):,}</span>", unsafe_allow_html=True)

    page_size = st.selectbox("Rows per page", [25, 50, 100, 200, 500], index=2)
    total_pages = max(1, (len(df) + page_size - 1) // page_size)
    page_no = st.number_input("Page", min_value=1, max_value=total_pages, value=1, step=1)

    start = (page_no - 1) * page_size
    end = start + page_size

    view_cols = ["District", "City", "Property Name", "Promoter / Developer Name",
                 "Promoter Mobile Number", "Promoter Email", "status", "assigned_to", "follow_up"]
    dfv = safe_df_cols(df, view_cols).iloc[start:end]
    st.dataframe(dfv, use_container_width=True, height=560)

elif PAGE_KEY == "Leads Pipeline":
    page_title("🧩 Leads (Update Status)", "Open one lead and update status, notes, follow-up.")

    df = leads_df.drop_duplicates("__hash").copy()
    df["display"] = df["__hash"].astype("string").map(lambda x: disp_map.get(str(x), str(x)[:6]))

    if len(df) == 0:
        st.info("No leads available for your role/filters.")
        st.stop()

    sel = st.selectbox("Select lead", df["display"].tolist())
    rev = {v: k for k, v in disp_map.items()}
    pid = str(rev.get(sel))
    row = df[df["__hash"].astype("string") == pid].iloc[0].to_dict()

    st.markdown(f"**{pid_to_code.get(pid, pid[:6])} — {row.get('Property Name','')}**")
    st.caption(row.get("Property Address", ""))

    c1, c2 = st.columns(2)
    with c1:
        status = st.selectbox(
            "Status",
            LEAD_STATUS,
            index=LEAD_STATUS.index(row.get("status", "New")) if row.get("status", "New") in LEAD_STATUS else 0,
        )
        assigned = st.text_input("Assigned to", value=row.get("assigned_to", ""))
    with c2:
        outcome = st.selectbox("Last call outcome (optional)", [""] + CALL_OUTCOMES, index=0)
        follow = st.text_input("Follow-up (date/note)", value=row.get("follow_up", ""))

    notes = st.text_area("Notes", value=row.get("notes", ""), height=120)

    save_disabled = not can(SECTION, "edit", ROLE)
    if save_disabled:
        st.info("Your role is read-only for edits.")

    if st.button("✅ Save Update", type="primary", disabled=save_disabled):
        upsert_lead_update(SECTION, pid, status, assigned, row.get("lead_source") or "Cold Call", notes, follow, outcome or None)
        audit(USER, "LEAD_UPDATE", f"section={SECTION} pid={pid_to_code.get(pid,pid[:6])} status={status}")
        st.success("Saved.")
        st.rerun()




elif PAGE_KEY == "Inventory (Sites)":
    page_title("🗂 Inventory (Sites)", "Create / update installed sites. Fast search + CRUD.")

    if not can(SECTION, "view", ROLE):
        st.error("You don't have permission to view this section.")
        st.stop()

    # search (server-side for speed)
    q = st.text_input("Search (Code / Property / City / District / Contact)", placeholder="Type to filter…")
    params: dict = {}
    sql = "SELECT * FROM inventory_sites"
    if q.strip():
        sql += " WHERE " + ilike_clause(['property_code','district','city','property_name','property_address','contact_person','contact_details'], 'q')
        params["q"] = sql_q(q)
    sql += " ORDER BY last_updated DESC LIMIT 2000"
    inv = qdf(sql, params)
    st.markdown(f"<span class='badge badge-strong'>Sites: {len(inv):,}</span>", unsafe_allow_html=True)

    tabs = st.tabs(["📋 View", "➕ Add / Edit", "🔁 Recount Screens"])
    with tabs[0]:
        st.dataframe(inv, use_container_width=True, height=520)
        if len(inv) and can(SECTION, "export", ROLE):
            st.download_button("⬇ Export sites (CSV)", data=df_to_csv_bytes(inv), file_name="inventory_sites.csv", mime="text/csv")

    with tabs[1]:
        if not can(SECTION, "edit", ROLE) and not can(SECTION, "add", ROLE):
            st.info("No add/edit permission.")
        else:
            # pick existing
            options = ["(New)"] + inv["property_id"].fillna("").astype(str).tolist()
            pick = st.selectbox("Select property_id to edit", options)
            row = {}
            if pick != "(New)" and len(inv):
                row = inv[inv["property_id"].astype(str) == pick].iloc[0].to_dict()

            with st.form("inv_form"):
                c1,c2,c3 = st.columns(3)
                with c1:
                    property_id = st.text_input("property_id", value=row.get("property_id","") or str(uuid.uuid4()) if pick=="(New)" else str(row.get("property_id","")))
                    property_code = st.text_input("property_code", value=row.get("property_code","") or "")
                    district = st.text_input("district", value=row.get("district","") or "")
                    city = st.text_input("city", value=row.get("city","") or "")
                with c2:
                    property_name = st.text_input("property_name", value=row.get("property_name","") or "")
                    property_address = st.text_area("property_address", value=row.get("property_address","") or "", height=90)
                    latitude = st.text_input("latitude", value=str(row.get("latitude","") or ""))
                    longitude = st.text_input("longitude", value=str(row.get("longitude","") or ""))
                with c3:
                    contact_person = st.text_input("contact_person", value=row.get("contact_person","") or "")
                    contact_details = st.text_input("contact_details", value=row.get("contact_details","") or "")
                    agreed_rent_pm = st.text_input("agreed_rent_pm", value=str(row.get("agreed_rent_pm","") or ""))
                    site_rating = st.number_input("site_rating (1-5)", 1, 5, int(row.get("site_rating") or 3))
                notes = st.text_area("notes", value=row.get("notes","") or "", height=80)

                ok = st.form_submit_button("Save", type="primary")
            if ok:
                exec_sql(
                    """INSERT INTO inventory_sites(property_id,property_code,district,city,property_name,property_address,latitude,longitude,contact_person,contact_details,agreed_rent_pm,site_rating,notes,last_updated)
                       VALUES(:property_id,:property_code,:district,:city,:property_name,:property_address,:latitude,:longitude,:contact_person,:contact_details,:agreed_rent_pm,:site_rating,:notes,NOW())
                       ON CONFLICT(property_id) DO UPDATE SET
                         property_code=EXCLUDED.property_code,
                         district=EXCLUDED.district,
                         city=EXCLUDED.city,
                         property_name=EXCLUDED.property_name,
                         property_address=EXCLUDED.property_address,
                         latitude=EXCLUDED.latitude,
                         longitude=EXCLUDED.longitude,
                         contact_person=EXCLUDED.contact_person,
                         contact_details=EXCLUDED.contact_details,
                         agreed_rent_pm=EXCLUDED.agreed_rent_pm,
                         site_rating=EXCLUDED.site_rating,
                         notes=EXCLUDED.notes,
                         last_updated=NOW()
                    """,
                    {
                        "property_id": property_id,
                        "property_code": property_code,
                        "district": district,
                        "city": city,
                        "property_name": property_name,
                        "property_address": property_address,
                        "latitude": float(latitude) if str(latitude).strip() else None,
                        "longitude": float(longitude) if str(longitude).strip() else None,
                        "contact_person": contact_person,
                        "contact_details": contact_details,
                        "agreed_rent_pm": float(agreed_rent_pm) if str(agreed_rent_pm).strip() else None,
                        "site_rating": int(site_rating),
                        "notes": notes,
                    },
                )
                audit(USER, "UPSERT_INVENTORY", f"{SECTION} {property_id}")
                st.success("Saved.")
                st.rerun()

    with tabs[2]:
        if st.button("Recalculate no_screens_installed for all inventory_sites"):
            if not can(SECTION, "edit", ROLE):
                st.error("No permission.")
            else:
                exec_sql("""
                    UPDATE inventory_sites s
                    SET no_screens_installed = COALESCE(x.cnt,0), last_updated=NOW()
                    FROM (
                      SELECT property_id, COUNT(*) AS cnt
                      FROM screens
                      WHERE is_active=1
                      GROUP BY property_id
                    ) x
                    WHERE s.property_id = x.property_id
                """)
                audit(USER, "RECOUNT_SCREENS", f"{SECTION}")
                st.success("Updated counts.")
                st.rerun()

elif PAGE_KEY == "Screens":
    page_title("🖥 Screens", "Register screens for a site and manage service due dates.")

    if not can(SECTION, "view", ROLE):
        st.error("You don't have permission to view this section.")
        st.stop()

    inv = qdf("SELECT property_id, property_code, property_name, city, district FROM inventory_sites ORDER BY property_name")
    prop = st.selectbox("Filter by property", ["(All)"] + inv["property_id"].fillna("").astype(str).tolist())
    params = {}
    sql = "SELECT * FROM screens "
    if prop != "(All)":
        sql += "WHERE property_id=:pid "
        params["pid"] = prop
    sql += "ORDER BY last_updated DESC LIMIT 3000"
    scr = qdf(sql, params)

q = st.text_input("Search screens", placeholder="location / installer / id …")
if q.strip():
    params2 = dict(params)
    base = """SELECT s.*, i.property_name, i.city, i.district
              FROM screens s
              LEFT JOIN inventory_sites i ON i.property_id = s.property_id"""
    if prop != "(All)":
        sql2 = base + " WHERE s.property_id=:pid AND " + ilike_clause(['s.screen_id','s.property_id','i.property_name','i.city','i.district','s.screen_location','s.installed_by'], 'q')
    else:
        sql2 = base + " WHERE " + ilike_clause(['s.screen_id','s.property_id','i.property_name','i.city','i.district','s.screen_location','s.installed_by'], 'q')
    params2["q"] = sql_q(q)
    scr = qdf(sql2 + " ORDER BY s.last_updated DESC LIMIT 3000", params2)

    st.markdown(f"<span class='badge badge-strong'>Screens: {len(scr):,}</span>", unsafe_allow_html=True)
    t1,t2 = st.tabs(["📋 View", "➕ Add / Edit"])
    with t1:
        st.dataframe(scr, use_container_width=True, height=520)
if (scr is not None) and (hasattr(scr, "empty") and not scr.empty) and can(SECTION, "export", ROLE):
    st.download_button("⬇ Export screens (CSV)", data=df_to_csv_bytes(scr), file_name="screens.csv", mime="text/csv")

    with t2:
        if not can(SECTION, "edit", ROLE) and not can(SECTION, "add", ROLE):
            st.info("No add/edit permission.")
        else:
            options = ["(New)"] + scr["screen_id"].fillna("").astype(str).tolist()
            pick = st.selectbox("Select screen_id to edit", options)
            row = {}
            if pick != "(New)" and len(scr):
                row = scr[scr["screen_id"].astype(str) == pick].iloc[0].to_dict()

            with st.form("screen_form"):
                c1,c2 = st.columns(2)
                with c1:
                    screen_id = st.text_input("screen_id", value=row.get("screen_id","") or str(uuid.uuid4()) if pick=="(New)" else str(row.get("screen_id","")))
                    property_id = st.selectbox("property_id", inv["property_id"].fillna("").astype(str).tolist(), index=0 if not row.get("property_id") else max(0, inv.index[inv["property_id"].astype(str)==str(row.get("property_id"))][0]))
                    screen_location = st.text_input("screen_location", value=row.get("screen_location","") or "")
                    installed_by = st.text_input("installed_by", value=row.get("installed_by","") or USER)
                with c2:
                    installed_date = st.text_input("installed_date (YYYY-MM-DD)", value=row.get("installed_date","") or "")
                    last_service_date = st.text_input("last_service_date (YYYY-MM-DD)", value=row.get("last_service_date","") or "")
                    next_service_due = st.text_input("next_service_due (YYYY-MM-DD)", value=row.get("next_service_due","") or "")
                    is_active = st.checkbox("Active", value=bool(int(row.get("is_active",1) or 1)))
                ok = st.form_submit_button("Save", type="primary")
            if ok:
                exec_sql(
                    """INSERT INTO screens(screen_id,property_id,screen_location,installed_date,installed_by,last_service_date,next_service_due,is_active,last_updated)
                       VALUES(:screen_id,:property_id,:screen_location,:installed_date,:installed_by,:last_service_date,:next_service_due,:is_active,NOW())
                       ON CONFLICT(screen_id) DO UPDATE SET
                         property_id=EXCLUDED.property_id,
                         screen_location=EXCLUDED.screen_location,
                         installed_date=EXCLUDED.installed_date,
                         installed_by=EXCLUDED.installed_by,
                         last_service_date=EXCLUDED.last_service_date,
                         next_service_due=EXCLUDED.next_service_due,
                         is_active=EXCLUDED.is_active,
                         last_updated=NOW()
                    """,
                    {
                        "screen_id": screen_id,
                        "property_id": property_id,
                        "screen_location": screen_location,
                        "installed_date": installed_date,
                        "installed_by": installed_by,
                        "last_service_date": last_service_date,
                        "next_service_due": next_service_due,
                        "is_active": 1 if is_active else 0,
                    },
                )
                audit(USER, "UPSERT_SCREEN", f"{SECTION} {screen_id}")
                st.success("Saved.")
                st.rerun()

elif PAGE_KEY == "Service Center":
    page_title("🛠 Service Center", "Upcoming service due list + mark serviced quickly.")

    if not can(SECTION, "view", ROLE):
        st.error("You don't have permission to view this section.")
        st.stop()

    days = st.slider("Show due within (days)", 1, 120, 30)
    today = date.today()
    cutoff = (today + timedelta(days=days)).isoformat()

    due = qdf(
        """SELECT s.*, i.property_name, i.city, i.district
           FROM screens s
           LEFT JOIN inventory_sites i ON i.property_id = s.property_id
           WHERE s.is_active=1 AND COALESCE(NULLIF(s.next_service_due,''),'9999-12-31') <= :cutoff
           ORDER BY s.next_service_due ASC
           LIMIT 2000""",
        {"cutoff": cutoff},
    )

    st.markdown(f"<span class='badge badge-strong'>Due: {len(due):,}</span>", unsafe_allow_html=True)
    st.dataframe(due, use_container_width=True, height=420)

    st.markdown("### ✅ Mark serviced")
    if len(due):
        sid = st.selectbox("Select screen_id", due["screen_id"].astype(str).tolist())
    else:
        sid = st.text_input("screen_id")

    c1,c2,c3 = st.columns(3)
    with c1:
        last_service_date = st.date_input("Last service date", value=today).isoformat()
    with c2:
        next_due = st.date_input("Next due date", value=today + timedelta(days=30)).isoformat()
    with c3:
        by_user = st.text_input("Serviced by", value=USER)
    if st.button("Update service dates", type="primary"):
        if not can(SECTION, "edit", ROLE):
            st.error("No permission.")
        else:
            exec_sql(
                "UPDATE screens SET last_service_date=:ls, next_service_due=:nd, last_updated=NOW() WHERE screen_id=:sid",
                {"ls": last_service_date, "nd": next_due, "sid": sid},
            )
            audit(USER, "MARK_SERVICED", f"{SECTION} {sid} ls={last_service_date} nd={next_due}")
            st.success("Updated.")
            st.rerun()

elif PAGE_KEY == "Ad Sales Inventory":
    page_title("📢 Ad Sales Inventory", "Track ad slots / bookings per screen or property.")

    if not can(SECTION, "view", ROLE):
        st.error("You don't have permission to view this section.")
        st.stop()

    q = st.text_input("Search bookings", placeholder="client / slot / property / screen …")
    params: dict = {"s": SECTION}
    sql = "SELECT * FROM ad_inventory WHERE section=:s"
    if q.strip():
        sql += " AND " + ilike_clause(['booking_id','property_id','client_name','screen_id','status','notes'], 'q')
        params["q"] = sql_q(q)
    sql += " ORDER BY updated_at DESC LIMIT 3000"
    ad = qdf(sql, params)

    st.markdown(f"<span class='badge badge-strong'>Records: {len(ad):,}</span>", unsafe_allow_html=True)
    t1,t2 = st.tabs(["📋 View", "➕ Add / Edit"])
    with t1:
        st.dataframe(ad, use_container_width=True, height=520)
if len(ad) and can(SECTION, "export", ROLE):
    st.download_button("⬇ Export bookings (CSV)", data=df_to_csv_bytes(ad), file_name="ad_inventory.csv", mime="text/csv")

    with t2:
        if not can(SECTION, "edit", ROLE) and not can(SECTION, "add", ROLE):
            st.info("No add/edit permission.")
        else:
            options = ["(New)"] + ad["ad_id"].fillna("").astype(str).tolist()
            pick = st.selectbox("Select ad_id to edit", options)
            row = {}
            if pick != "(New)" and len(ad):
                row = ad[ad["ad_id"].astype(str) == pick].iloc[0].to_dict()

            inv = qdf("SELECT property_id, property_name, city FROM inventory_sites ORDER BY property_name LIMIT 5000")
            pid_list = inv["property_id"].fillna("").astype(str).tolist()
            with st.form("ad_form"):
                c1,c2,c3 = st.columns(3)
                with c1:
                    ad_id = st.text_input("ad_id", value=row.get("ad_id","") or str(uuid.uuid4()) if pick=="(New)" else str(row.get("ad_id","")))
                    property_id = st.selectbox("property_id", [""] + pid_list, index=0)
                    screen_id = st.text_input("screen_id", value=row.get("screen_id","") or "")
                    slot_name = st.text_input("slot_name", value=row.get("slot_name","") or "Main")
                with c2:
                    start_date = st.text_input("start_date (YYYY-MM-DD)", value=row.get("start_date","") or "")
                    end_date = st.text_input("end_date (YYYY-MM-DD)", value=row.get("end_date","") or "")
                    rate = st.text_input("rate", value=str(row.get("rate","") or ""))
                    status = st.selectbox("status", ["Available","Booked","Hold","Completed","Cancelled"], index=0)
                with c3:
                    client_name = st.text_input("client_name", value=row.get("client_name","") or "")
                    notes = st.text_area("notes", value=row.get("notes","") or "", height=110)
                ok = st.form_submit_button("Save", type="primary")
            if ok:
                exec_sql(
                    """INSERT INTO ad_inventory(ad_id,section,property_id,screen_id,slot_name,start_date,end_date,rate,status,client_name,notes,created_by,created_at,updated_at)
                       VALUES(:ad_id,:section,:property_id,:screen_id,:slot_name,:start_date,:end_date,:rate,:status,:client_name,:notes,:created_by,NOW(),NOW())
                       ON CONFLICT(ad_id) DO UPDATE SET
                         property_id=EXCLUDED.property_id,
                         screen_id=EXCLUDED.screen_id,
                         slot_name=EXCLUDED.slot_name,
                         start_date=EXCLUDED.start_date,
                         end_date=EXCLUDED.end_date,
                         rate=EXCLUDED.rate,
                         status=EXCLUDED.status,
                         client_name=EXCLUDED.client_name,
                         notes=EXCLUDED.notes,
                         updated_at=NOW()
                    """,
                    {
                        "ad_id": ad_id,
                        "section": SECTION,
                        "property_id": property_id or None,
                        "screen_id": screen_id or None,
                        "slot_name": slot_name,
                        "start_date": start_date,
                        "end_date": end_date,
                        "rate": float(rate) if str(rate).strip() else None,
                        "status": status,
                        "client_name": client_name,
                        "notes": notes,
                        "created_by": USER,
                    },
                )
                audit(USER, "UPSERT_AD_INVENTORY", f"{SECTION} {ad_id}")
                st.success("Saved.")
                st.rerun()

elif PAGE_KEY == "Agreements":
    page_title("📝 Agreements", "Manage agreements per property (rent, dates, status).")

    if not can(SECTION, "view", ROLE):
        st.error("You don't have permission to view this section.")
        st.stop()

    q = st.text_input("Search agreements", placeholder="property / party / code …")
    params: dict = {"s": SECTION}
    sql = "SELECT * FROM agreements WHERE section=:s"
    if q.strip():
        sql += " AND " + ilike_clause(['agreement_id','property_id','party_name','property_code','status','billing_cycle','notes'], 'q')
        params["q"] = sql_q(q)
    sql += " ORDER BY updated_at DESC LIMIT 3000"
    ag = qdf(sql, params)

    st.markdown(f"<span class='badge badge-strong'>Agreements: {len(ag):,}</span>", unsafe_allow_html=True)
    t1,t2 = st.tabs(["📋 View", "➕ Add / Edit"])
    with t1:
        st.dataframe(ag, use_container_width=True, height=520)
if len(ag) and can(SECTION, "export", ROLE):
    st.download_button("⬇ Export agreements (CSV)", data=df_to_csv_bytes(ag), file_name="agreements.csv", mime="text/csv")

    with t2:
        if not can(SECTION, "edit", ROLE) and not can(SECTION, "add", ROLE):
            st.info("No add/edit permission.")
        else:
            options = ["(New)"] + ag["agreement_id"].fillna("").astype(str).tolist()
            pick = st.selectbox("Select agreement_id", options)
            row = {}
            if pick != "(New)" and len(ag):
                row = ag[ag["agreement_id"].astype(str) == pick].iloc[0].to_dict()
            inv = qdf("SELECT property_id, property_code, property_name FROM inventory_sites ORDER BY property_name LIMIT 5000")
            pid_list = inv["property_id"].fillna("").astype(str).tolist()

            with st.form("ag_form"):
                c1,c2,c3 = st.columns(3)
                with c1:
                    agreement_id = st.text_input("agreement_id", value=row.get("agreement_id","") or str(uuid.uuid4()) if pick=="(New)" else str(row.get("agreement_id","")))
                    property_id = st.selectbox("property_id", [""] + pid_list, index=0)
                    property_code = st.text_input("property_code", value=row.get("property_code","") or "")
                    party_name = st.text_input("party_name", value=row.get("party_name","") or "")
                with c2:
                    start_date = st.text_input("start_date (YYYY-MM-DD)", value=row.get("start_date","") or "")
                    end_date = st.text_input("end_date (YYYY-MM-DD)", value=row.get("end_date","") or "")
                    renewal_type = st.selectbox("renewal_type", ["Fixed","Auto-Renew","Month-to-Month","Other"], index=0)
                    billing_cycle = st.selectbox("billing_cycle", ["Monthly","Quarterly","Half-yearly","Yearly","Other"], index=0)
                with c3:
                    rent_pm = st.text_input("rent_pm", value=str(row.get("rent_pm","") or ""))
                    status = st.selectbox("status", ["Active","Expired","Terminated","Draft"], index=0)
                    notes = st.text_area("notes", value=row.get("notes","") or "", height=110)
                ok = st.form_submit_button("Save", type="primary")
            if ok:
                exec_sql(
                    """INSERT INTO agreements(agreement_id,section,property_id,property_code,party_name,start_date,end_date,renewal_type,rent_pm,billing_cycle,status,notes,created_by,created_at,updated_at)
                       VALUES(:id,:sec,:pid,:pc,:party,:sd,:ed,:rt,:rent,:bc,:st,:notes,:by,NOW(),NOW())
                       ON CONFLICT(agreement_id) DO UPDATE SET
                        property_id=EXCLUDED.property_id,
                        property_code=EXCLUDED.property_code,
                        party_name=EXCLUDED.party_name,
                        start_date=EXCLUDED.start_date,
                        end_date=EXCLUDED.end_date,
                        renewal_type=EXCLUDED.renewal_type,
                        rent_pm=EXCLUDED.rent_pm,
                        billing_cycle=EXCLUDED.billing_cycle,
                        status=EXCLUDED.status,
                        notes=EXCLUDED.notes,
                        updated_at=NOW()
                    """,
                    {
                        "id": agreement_id,
                        "sec": SECTION,
                        "pid": property_id or None,
                        "pc": property_code,
                        "party": party_name,
                        "sd": start_date,
                        "ed": end_date,
                        "rt": renewal_type,
                        "rent": float(rent_pm) if str(rent_pm).strip() else None,
                        "bc": billing_cycle,
                        "st": status,
                        "notes": notes,
                        "by": USER,
                    },
                )
                audit(USER, "UPSERT_AGREEMENT", f"{SECTION} {agreement_id}")
                st.success("Saved.")
                st.rerun()

elif PAGE_KEY == "Billing & Reminders":
    page_title("💰 Billing & Reminders", "Track due payments, paid status and reminders. (Fast search + export)")

    if not can(SECTION, "view", ROLE):
        st.error("You don't have permission to view this section.")
        st.stop()

    top1, top2, top3 = st.columns([2,2,1])
    with top1:
        q = st.text_input("Search payments", placeholder="agreement / status / notes …")
    with top2:
        days = st.slider("Show dues within (days)", 1, 365, 45)
    with top3:
        show_all = st.checkbox("Show all", value=False)

    cutoff = (date.today() + timedelta(days=days)).isoformat()

    params: dict = {"s": SECTION}
    sql = "SELECT * FROM payments WHERE section=:s"
    if not show_all:
        sql += " AND (due_date <= :cutoff) AND (status IS NULL OR status ILIKE 'due' OR status ILIKE 'pending')"
        params["cutoff"] = cutoff
    if q.strip():
        sql += " AND " + ilike_clause(['payment_id','agreement_id','status','notes'], 'q')
        params["q"] = sql_q(q)
    sql += " ORDER BY due_date ASC NULLS LAST, updated_at DESC LIMIT 5000"

    pay = qdf(sql, params)
    st.markdown(f"<span class='badge badge-strong'>Payments: {len(pay):,}</span>", unsafe_allow_html=True)

    t1, t2 = st.tabs(["📋 Due / Payments", "➕ Add / Update Payment"])
    with t1:
        st.dataframe(pay, use_container_width=True, height=520)
        if len(pay) and can(SECTION, "export", ROLE):
            st.download_button("⬇ Export payments (CSV)", data=df_to_csv_bytes(pay), file_name="payments.csv", mime="text/csv")

    with t2:
        if not (can(SECTION, "add", ROLE) or can(SECTION, "edit", ROLE)):
            st.info("No add/edit permission.")
        else:
            with st.form("pay_add", clear_on_submit=True):
                pid = st.text_input("Payment ID (leave blank to auto-generate)").strip()
                agreement_id = st.text_input("Agreement ID").strip()
                amount = st.number_input("Amount", min_value=0.0, value=0.0, step=500.0)
                due_date = st.date_input("Due date", value=date.today() + timedelta(days=15)).isoformat()
                status = st.selectbox("Status", ["due", "pending", "paid", "cancelled"], index=0)
                paid_date = st.date_input("Paid date (if paid)", value=date.today()).isoformat() if status == "paid" else ""
                notes = st.text_area("Notes", height=80)
                save = st.form_submit_button("Save payment", type="primary")
                if save:
                    errs = []
                    if not agreement_id:
                        errs.append("Agreement ID is required.")
                    if amount <= 0:
                        errs.append("Amount must be > 0.")
                    if errs:
                        st.error(" | ".join(errs))
                    else:
                        pid = pid or str(uuid.uuid4())
                        exec_sql(
                            """INSERT INTO payments(payment_id, section, agreement_id, amount, due_date, status, paid_date, notes, created_by, updated_at)
                                   VALUES(:pid,:sec,:aid,:amt,:dd,:st,:pd,:nt,:by,NOW())
                                   ON CONFLICT(payment_id) DO UPDATE SET
                                     agreement_id=excluded.agreement_id,
                                     amount=excluded.amount,
                                     due_date=excluded.due_date,
                                     status=excluded.status,
                                     paid_date=excluded.paid_date,
                                     notes=excluded.notes,
                                     updated_at=NOW()""",
                            {"pid": pid, "sec": SECTION, "aid": agreement_id, "amt": float(amount), "dd": due_date, "st": status, "pd": paid_date, "nt": notes, "by": USER},
                        )
                        audit(USER, "PAYMENT_UPSERT", f"{SECTION} {pid} {agreement_id} {status} {amount}")
                        st.success("Saved.")
                        st.rerun()

elif PAGE_KEY == "Documents Vault":

    page_title("📄 Documents Vault", "Upload / track documents linked to properties.")

    if not can(SECTION, "view", ROLE):
        st.error("You don't have permission to view this section.")
        st.stop()

    Path("uploads").mkdir(exist_ok=True)

    q = st.text_input("Search documents", placeholder="doc type / filename / property …")
    params: dict = {"s": SECTION}
    sql = "SELECT * FROM documents_vault WHERE section=:s"
    if q.strip():
        sql += " AND " + ilike_clause(['doc_id','property_id','doc_type','filename','uploaded_by'], 'q')
        params["q"] = sql_q(q)
    sql += " ORDER BY uploaded_at DESC LIMIT 5000"
    docs = qdf(sql, params)

    t1,t2 = st.tabs(["📋 View", "⬆ Upload"])
    with t1:
        st.dataframe(docs, use_container_width=True, height=420)
        if len(docs) and can(SECTION, "export", ROLE):
            st.download_button("⬇ Export documents (CSV)", data=df_to_csv_bytes(docs), file_name="documents_vault.csv", mime="text/csv")
        if len(docs):
            pick = st.selectbox("Download file", [""] + docs["doc_id"].astype(str).tolist())
            if pick:
                row = docs[docs["doc_id"].astype(str) == pick].iloc[0].to_dict()
                pth = row.get("storage_path") or ""
                if pth and Path(pth).exists():
                    data = Path(pth).read_bytes()
                    st.download_button("Download", data=data, file_name=row.get("filename","document.bin"))
                else:
                    st.warning("File not found on server storage (may be cleared on hosting).")

    with t2:
        if not can(SECTION, "add", ROLE):
            st.info("No upload permission.")
        else:
            inv = qdf("SELECT property_id, property_name FROM inventory_sites ORDER BY property_name LIMIT 5000")
            pid_list = inv["property_id"].fillna("").astype(str).tolist()
            with st.form("doc_upload"):
                property_id = st.selectbox("property_id", [""] + pid_list, index=0)
                doc_type = st.text_input("doc_type", value="Agreement")
                issue_date = st.text_input("issue_date (YYYY-MM-DD)", value="")
                expiry_date = st.text_input("expiry_date (YYYY-MM-DD)", value="")
                up = st.file_uploader("Choose file", type=None)
                ok = st.form_submit_button("Upload", type="primary")
            if ok:
                if not up:
                    st.error("Please choose a file.")
                else:
                    doc_id = str(uuid.uuid4())
                    fname = re.sub(r"[^A-Za-z0-9._-]+", "_", up.name)
                    storage_path = str(Path("uploads") / f"{doc_id}_{fname}")
                    Path(storage_path).write_bytes(up.getbuffer())
                    exec_sql(
                        """INSERT INTO documents_vault(doc_id,section,property_id,doc_type,filename,storage_path,issue_date,expiry_date,uploaded_by)
                           VALUES(:id,:sec,:pid,:dt,:fn,:sp,:is,:ex,:by)
                        """,
                        {
                            "id": doc_id,
                            "sec": SECTION,
                            "pid": property_id or None,
                            "dt": doc_type,
                            "fn": fname,
                            "sp": storage_path,
                            "is": issue_date,
                            "ex": expiry_date,
                            "by": USER,
                        },
                    )
                    audit(USER, "UPLOAD_DOC", f"{SECTION} {doc_id} {fname}")
                    st.success("Uploaded.")
                    st.rerun()

elif PAGE_KEY == "Map View":
    page_title("🗺 Map View", "View sites on map (requires latitude/longitude).")

    if not can(SECTION, "view", ROLE):
        st.error("You don't have permission to view this section.")
        st.stop()

    inv = qdf("SELECT property_name, city, district, latitude, longitude FROM inventory_sites WHERE latitude IS NOT NULL AND longitude IS NOT NULL LIMIT 5000")
    if len(inv) == 0:
        st.info("No sites with coordinates yet. Fill latitude/longitude in Inventory.")
    else:
        st.map(inv.rename(columns={"latitude":"lat","longitude":"lon"}), zoom=10)

else:
    st.info("This page is not implemented yet in this build.")
