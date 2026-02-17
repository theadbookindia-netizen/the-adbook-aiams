import os
import re
import io
import uuid
import json
import hashlib
from datetime import date, timedelta
from urllib.parse import quote_plus, urlparse, urlunparse, parse_qsl, urlencode

import numpy as np
import pandas as pd
import streamlit as st

from sqlalchemy import create_engine, text

# PDF (Cloud-safe)
from io import BytesIO
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas


# =============================================================================
# CONFIG
# =============================================================================
APP_TITLE = "The Adbook — AIAMS v1.0 (Supabase Full)"
WEBSITE_URL = "https://theadbookoutdoor.com/"
DATA_FILE = "property_data.csv"

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

BILLING_CYCLES = ["One-time", "Monthly", "Quarterly", "Yearly"]

DOC_TYPES_INSTALL = ["Society Agreement Copy", "Permission Letter", "NOC", "Installation Checklist", "Agreement Copy", "Property Photo", "Other"]
DOC_TYPES_ADS = ["Advertisement Agreement", "Subscription Agreement", "Invoice Copy", "Receipt", "Creative/Artwork", "Other"]

UPLOAD_ROOT = "uploads_docs"
UPLOAD_INSTALL = os.path.join(UPLOAD_ROOT, "installation")
UPLOAD_ADS = os.path.join(UPLOAD_ROOT, "advertisement")
UPLOAD_SIG = os.path.join(UPLOAD_ROOT, "signatures")
os.makedirs(UPLOAD_INSTALL, exist_ok=True)
os.makedirs(UPLOAD_ADS, exist_ok=True)
os.makedirs(UPLOAD_SIG, exist_ok=True)


# =============================================================================
# UI
# =============================================================================
st.set_page_config(page_title=APP_TITLE, layout="wide", page_icon="🟧")
st.markdown(
    """
<style>
:root{
  --bg:#ffffff; --surface:#ffffff; --surface2:#f6f8fb; --border:#e6e8ef;
  --text:#0f172a; --muted:#475569; --accent:#0f5b66; --warn:#b45309; --danger:#b91c1c;
}
.block-container{max-width:1560px;padding-top:.65rem;padding-bottom:2rem;}
[data-testid="stAppViewContainer"]{background:var(--bg);}
[data-testid="stHeader"]{background:rgba(255,255,255,.92);border-bottom:1px solid var(--border);}
[data-testid="stSidebar"]{background:var(--surface2);border-right:1px solid var(--border);}
.card{background:var(--surface);border:1px solid var(--border);border-radius:18px;padding:14px;box-shadow:0 8px 24px rgba(15,23,42,.06);}
.small{color:var(--muted);font-size:.92rem;}
.section{font-weight:850;font-size:1.05rem;margin:0 0 .25rem 0;}
.kpi{background:#fff;border:1px solid var(--border);border-radius:16px;padding:10px 12px;}
.kpi .label{color:var(--muted);font-size:.85rem;margin-bottom:2px;}
.kpi .val{font-weight:850;font-size:1.25rem;color:var(--text);}
.sticky-wrap{position:sticky;top:0;z-index:999;background:rgba(255,255,255,.96);backdrop-filter:blur(6px);
  border-bottom:1px solid var(--border);padding:8px 0 10px 0;margin-bottom:10px;}
div.stButton>button{width:100%;border-radius:12px;padding:.65rem .9rem;font-weight:650;border:1px solid var(--border);}
div.stButton>button[kind="primary"]{background:var(--accent);color:#fff;border:1px solid rgba(15,91,102,.35);}
hr{border:0;border-top:1px solid var(--border);margin:1rem 0;}
</style>
""",
    unsafe_allow_html=True,
)


# =============================================================================
# DATABASE URL FIXES (Supabase + psycopg v3 + sslmode=require)
# =============================================================================
def _force_psycopg_driver(db_url: str) -> str:
    """
    If user gives: postgresql://... we convert to: postgresql+psycopg://...
    This avoids 'import psycopg2' error on Streamlit Cloud.
    """
    if db_url.startswith("postgresql://"):
        return db_url.replace("postgresql://", "postgresql+psycopg://", 1)
    if db_url.startswith("postgres://"):
        return db_url.replace("postgres://", "postgresql+psycopg://", 1)
    return db_url

def _ensure_sslmode_require(db_url: str) -> str:
    """
    Supabase often requires SSL. Add sslmode=require if missing.
    """
    try:
        p = urlparse(db_url)
        q = dict(parse_qsl(p.query, keep_blank_values=True))
        if "sslmode" not in q:
            q["sslmode"] = "require"
            new_query = urlencode(q)
            p2 = p._replace(query=new_query)
            return urlunparse(p2)
        return db_url
    except Exception:
        return db_url

def get_database_url() -> str:
    """
    Reads DATABASE_URL from Streamlit secrets or environment.
    Then fixes:
      - driver to psycopg v3
      - adds sslmode=require
    """
    db_url = ""
    try:
        if "DATABASE_URL" in st.secrets:
            db_url = str(st.secrets["DATABASE_URL"]).strip()
    except Exception:
        pass

    if not db_url:
        db_url = os.environ.get("DATABASE_URL", "").strip()

    db_url = _force_psycopg_driver(db_url)
    db_url = _ensure_sslmode_require(db_url)
    return db_url

@st.cache_resource(show_spinner=False)
def db_engine():
    db_url = get_database_url()
    if not db_url:
        st.error("DATABASE_URL not found.\n\nAdd it in Streamlit Secrets:\n- App → Settings → Secrets\n\nExample:\nDATABASE_URL = \"postgresql+psycopg://USER:PASSWORD@HOST:5432/postgres?sslmode=require\"")
        st.stop()
    return create_engine(db_url, pool_pre_ping=True)

def exec_sql(sql: str, params: dict | None = None):
    with db_engine().begin() as conn:
        conn.execute(text(sql), params or {})

def qdf(sql: str, params: dict | None = None) -> pd.DataFrame:
    with db_engine().connect() as conn:
        return pd.read_sql(text(sql), conn, params=params or {})


# =============================================================================
# DB MIGRATIONS
# =============================================================================
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
    CREATE TABLE IF NOT EXISTS whatsapp_logs_v8(
      log_id TEXT PRIMARY KEY,
      campaign_id TEXT,
      lead_hash TEXT,
      username TEXT,
      action_status TEXT,
      created_at TIMESTAMP DEFAULT NOW()
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


# =============================================================================
# SEED PERMISSIONS
# =============================================================================
def seed_permissions_once():
    try:
        c = int(qdf("SELECT COUNT(*) AS c FROM permissions").iloc[0]["c"] or 0)
    except Exception:
        c = 0

    if c == 0:
        for role, sections in DEFAULT_PERMS.items():
            for sec, perm in sections.items():
                exec_sql(
                    """INSERT INTO permissions(id,role,section,can_view,can_add,can_edit,can_delete,can_export)
                       VALUES(:id,:role,:section,:v,:a,:e,:d,:x)""",
                    {"id": str(uuid.uuid4()), "role": role, "section": sec,
                     "v": int(perm["view"]), "a": int(perm["add"]), "e": int(perm["edit"]),
                     "d": int(perm["delete"]), "x": int(perm["export"])}
                )

seed_permissions_once()


# =============================================================================
# AUTH HELPERS
# =============================================================================
def pbkdf2_hash(password: str, salt: str | None = None) -> str:
    salt = salt or uuid.uuid4().hex
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 120_000)
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
    exec_sql("INSERT INTO audit_logs(log_id,username,action_type,details) VALUES(:id,:u,:a,:d)",
             {"id": str(uuid.uuid4()), "u": user, "a": action, "d": details})

def get_user(username):
    df = qdf("SELECT * FROM users WHERE username=:u", {"u": username})
    return df.iloc[0].to_dict() if len(df) else None

def set_last_login(username):
    exec_sql("UPDATE users SET last_login_at=NOW(), updated_at=NOW() WHERE username=:u", {"u": username})

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


# =============================================================================
# LOGIN UI
# =============================================================================
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

        st.caption("If first time: create SuperAdmin user from Supabase SQL editor (instructions at bottom).")
        st.stop()

require_auth()
AUTH = st.session_state["auth"]
USER = AUTH["user"]
ROLE = AUTH["role"]
SCOPE = AUTH.get("scope", SCOPE_BOTH)


# =============================================================================
# DATA HELPERS
# =============================================================================
@st.cache_data(show_spinner=False)
def read_leads_file(upload=None):
    if upload is None:
        if not os.path.exists(DATA_FILE):
            st.error(f"Missing {DATA_FILE}. Put it in same folder as app.py")
            st.stop()
        df = pd.read_csv(DATA_FILE, encoding="utf-8-sig", low_memory=False)
    else:
        name = upload.name.lower()
        if name.endswith(".csv"):
            df = pd.read_csv(upload, encoding="utf-8-sig", low_memory=False)
        else:
            xl = pd.ExcelFile(upload)
            sheet = st.selectbox("Sheet", xl.sheet_names)
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

def whatsapp_url(mobile, message):
    m = normalize_mobile(mobile)
    if not m:
        return "#"
    return f"https://wa.me/91{m}?text={quote_plus(message)}"

def kpi(label, value):
    st.markdown(f"<div class='kpi'><div class='label'>{label}</div><div class='val'>{value}</div></div>",
                unsafe_allow_html=True)

def page_title(title, subtitle):
    st.markdown(f"<div class='card'><div class='section'>{title}</div><div class='small'>{subtitle}</div></div>",
                unsafe_allow_html=True)


# =============================================================================
# PROPERTY CODES
# =============================================================================
def _letters2(x):
    x = re.sub(r"[^A-Za-z]", "", (x or "").upper())
    return (x + "XX")[:2]

def ensure_property_codes(leads_df: pd.DataFrame) -> pd.DataFrame:
    needed = leads_df[["__hash", "District", "City", "Property Name"]].drop_duplicates().copy()
    needed.columns = ["property_id", "district", "city", "property_name"]

    existing = qdf("SELECT property_id, property_code FROM property_codes")
    existing_map = dict(zip(existing["property_id"].astype("string"), existing["property_code"].astype("string"))) if len(existing) else {}

    rows_to_insert = []
    for r in needed.to_dict("records"):
        pid = str(r["property_id"])
        if pid in existing_map and existing_map[pid] and existing_map[pid] != "nan":
            continue

        prefix = _letters2(r.get("district")) + _letters2(r.get("city"))
        used = qdf("SELECT property_code FROM property_codes WHERE property_code LIKE :p", {"p": f"{prefix}%"})
        used_codes = set(used["property_code"].dropna().astype("string").tolist()) if len(used) else set()

        n = 1
        while True:
            code = f"{prefix}{n:03d}"
            if code not in used_codes:
                break
            n += 1
            if n > 999:
                code = f"{prefix}{uuid.uuid4().hex[:3].upper()}"
                break

        rows_to_insert.append({
            "property_id": pid,
            "property_code": code,
            "district": r.get("district", ""),
            "city": r.get("city", ""),
            "property_name": r.get("property_name", ""),
        })

    for row in rows_to_insert:
        tries = 0
        while True:
            try:
                exec_sql("""
                INSERT INTO property_codes(property_id,property_code,district,city,property_name)
                VALUES(:property_id,:property_code,:district,:city,:property_name)
                """, row)
                break
            except Exception:
                tries += 1
                if tries > 10:
                    row["property_code"] = f"{row['property_code'][:4]}{uuid.uuid4().hex[:3].upper()}"
                else:
                    cur = row["property_code"]
                    prefix = cur[:4]
                    try:
                        num = int(cur[4:7]) + 1
                    except Exception:
                        num = tries + 1
                    row["property_code"] = f"{prefix}{num:03d}"

    return qdf("SELECT property_id, property_code FROM property_codes")

def property_display_map(code_df, leads_df):
    name_map = leads_df.drop_duplicates("__hash").set_index("__hash")[["Property Name", "City"]].to_dict("index")
    out = {}
    for pid, code in zip(code_df["property_id"].astype("string"), code_df["property_code"].astype("string")):
        info = name_map.get(pid, {})
        nm = (info.get("Property Name") or "").strip()
        ct = (info.get("City") or "").strip()
        out[pid] = f"{code} — {nm[:45]} — {ct}" if nm or ct else f"{code} — {pid[:6]}"
    return out


# =============================================================================
# LEAD UPDATES
# =============================================================================
def list_lead_updates(section):
    return qdf("SELECT * FROM lead_updates_v8 WHERE section=:s", {"s": section})

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


# =============================================================================
# COMPANY SETTINGS / USER PROFILE
# =============================================================================
def get_company_settings():
    df = qdf("SELECT * FROM company_settings_v8 LIMIT 1")
    if len(df) == 0:
        sid = str(uuid.uuid4())
        exec_sql("INSERT INTO company_settings_v8(settings_id, gst_no, bank_details, whatsapp_limit_per_hour) VALUES(:i,'','',50)",
                 {"i": sid})
        df = qdf("SELECT * FROM company_settings_v8 LIMIT 1")
    return df.iloc[0].to_dict()

def upsert_company_settings(gst_no: str, bank_details: str, limit_per_hour: int):
    cur = get_company_settings()
    exec_sql("""
    UPDATE company_settings_v8
    SET gst_no=:g, bank_details=:b, whatsapp_limit_per_hour=:l, updated_at=NOW()
    WHERE settings_id=:id
    """, {"g": gst_no, "b": bank_details, "l": int(limit_per_hour), "id": cur["settings_id"]})

def get_user_profile(username: str):
    df = qdf("SELECT * FROM user_profiles_v8 WHERE username=:u", {"u": username})
    if len(df) == 0:
        exec_sql("INSERT INTO user_profiles_v8(username, signature_filename, designation, mobile, email) VALUES(:u,'','','','')", {"u": username})
        df = qdf("SELECT * FROM user_profiles_v8 WHERE username=:u", {"u": username})
    return df.iloc[0].to_dict()

def update_user_signature(username: str, filename: str):
    exec_sql("UPDATE user_profiles_v8 SET signature_filename=:f, updated_at=NOW() WHERE username=:u",
             {"u": username, "f": filename})


# =============================================================================
# PDF PROPOSAL (REPORTLAB)
# =============================================================================
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

    proposal_no = data.get("proposal_no", "")
    today = date.today().strftime("%d-%b-%Y")
    valid_till = (date.today() + timedelta(days=validity_days)).strftime("%d-%b-%Y")

    c.setFont("Helvetica", 10)
    c.drawRightString(width - left, height - 40, f"Proposal No: {proposal_no}")
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
    scope_points = data.get("scope_points", []) or []
    if not scope_points:
        line("• Scope to be finalized.", 11, False, 14)
    else:
        for s in scope_points:
            line(f"• {s}", 11, False, 14)

    hr()

    line("Pricing", 11, True, 16)
    pricing_rows = data.get("pricing_rows", []) or []
    if not pricing_rows:
        line("• Pricing to be finalized after discussion.", 11, False, 14)
    else:
        for pr in pricing_rows:
            item = pr.get("item", "")
            amount = pr.get("amount", "")
            notes = pr.get("notes", "")
            line(f"• {item} | INR {amount} | {notes}", 11, False, 14)

    hr()

    line("Timeline", 11, True, 16)
    timeline_points = data.get("timeline_points", []) or []
    if not timeline_points:
        line("• Timeline to be finalized.", 11, False, 14)
    else:
        for t in timeline_points:
            line(f"• {t}", 11, False, 14)

    hr()

    line("Payment Terms", 11, True, 16)
    payment_terms = data.get("payment_terms", []) or []
    if not payment_terms:
        line("• Payment terms to be finalized.", 11, False, 14)
    else:
        for p in payment_terms:
            line(f"• {p}", 11, False, 14)

    hr()

    line("GST", 11, True, 16)
    line(settings.get("gst_no", "Applicable as per rules.") or "Applicable as per rules.", 11, False, 16)

    line("Bank Details", 11, True, 16)
    bank_details = (settings.get("bank_details", "") or "").strip()
    if not bank_details:
        line("Will be shared on request.", 11, False, 14)
    else:
        for bl in bank_details.splitlines():
            line(bl, 11, False, 14)

    hr()

    line("For The Adbook Outdoor", 11, True, 16)
    line(f"Name: {signer.get('username','')}", 11, False, 14)
    line(f"Designation: {signer.get('designation','')}", 11, False, 14)

    c.setFont("Helvetica", 9)
    c.drawString(left, 30, "This proposal is system-generated by AIAMS (Cloud-safe PDF).")

    c.save()
    return buffer.getvalue()

def next_proposal_no():
    df = qdf("SELECT MAX(proposal_no) AS m FROM proposals_v8")
    m = df.iloc[0]["m"]
    return int(m or 0) + 1

def save_proposal_pdf(section: str, property_id: str, advertiser_id: str | None, pdf_bytes: bytes, created_by: str) -> dict:
    pno = next_proposal_no()
    fname = f"proposal_{section.lower()}_{pno}_{uuid.uuid4().hex}.pdf"
    folder = UPLOAD_INSTALL if section == SECTION_INSTALL else UPLOAD_ADS
    path = os.path.join(folder, fname)
    with open(path, "wb") as f:
        f.write(pdf_bytes)

    exec_sql("""
    INSERT INTO proposals_v8(proposal_id, section, property_id, advertiser_id, proposal_no, created_by, pdf_filename, status)
    VALUES(:id,:sec,:pid,:aid,:pno,:by,:fn,'Generated')
    """, {"id": str(uuid.uuid4()), "sec": section, "pid": property_id, "aid": advertiser_id or "", "pno": int(pno), "by": created_by, "fn": fname})

    return {"proposal_no": pno, "filename": fname, "path": path}

def whatsapp_rate_ok(username: str, limit_per_hour: int) -> bool:
    df = qdf("SELECT COUNT(*) AS c FROM whatsapp_logs_v8 WHERE username=:u AND created_at >= (NOW() - INTERVAL '1 hour')", {"u": username})
    c = int(df.iloc[0]["c"] or 0)
    return c < int(limit_per_hour)


# =============================================================================
# SIDEBAR (NAV)
# =============================================================================
with st.sidebar:
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

    MENU_INSTALL = ["Home", "Leads", "Inventory", "Screens", "Service Center", "Documents", "Proposals", "WhatsApp", "Reports"]
    MENU_ADS = ["Home", "Leads", "Proposals", "WhatsApp", "Reports"]
    menu = MENU_INSTALL if SECTION == SECTION_INSTALL else MENU_ADS
    if ROLE == ROLE_SUPERADMIN:
        menu = menu + ["Admin Panel"]
    PAGE = st.selectbox("Page", menu)


# =============================================================================
# LOAD LEADS + HASH
# =============================================================================
leads_df = read_leads_file(upload).copy()

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

codes_df = ensure_property_codes(leads_df)
disp_map = property_display_map(codes_df, leads_df)
pid_to_code = dict(zip(codes_df["property_id"].astype("string"), codes_df["property_code"].astype("string")))

upd = list_lead_updates(SECTION)
leads_df = leads_df.merge(upd, left_on="__hash", right_on="record_hash", how="left")
leads_df["status"] = leads_df["status"].fillna("New")
leads_df["assigned_to"] = leads_df["assigned_to"].fillna("")
leads_df["lead_source"] = leads_df["lead_source"].fillna("")
leads_df["notes"] = leads_df["notes"].fillna("")
leads_df["follow_up"] = leads_df["follow_up"].fillna("")

if ROLE in [ROLE_INSTALL_FIELD, ROLE_ADS_FIELD, ROLE_VIEWER]:
    leads_df = leads_df[leads_df["assigned_to"].astype("string") == USER]


# =============================================================================
# KPI BAR
# =============================================================================
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


# =============================================================================
# PAGES
# =============================================================================
if PAGE == "Home":
    page_title("🏠 Home (Search)", f"{SECTION}: search properties and contact quickly.")
    q = st.text_input("Search (Property / Promoter / Phone / Email)")
    df = leads_df.copy()
    if q.strip():
        s = q.strip().lower()
        cols = ["Property Name", "Property Address", "Promoter / Developer Name", "Promoter Email", "Promoter Mobile Number", "District", "City"]
        mask = pd.Series(False, index=df.index)
        for c in cols:
            mask |= df[c].astype("string").fillna("").str.lower().str.contains(re.escape(s), na=False)
        df = df[mask]
    st.dataframe(
        df[["District", "City", "Property Name", "Promoter / Developer Name", "Promoter Mobile Number", "Promoter Email", "status", "assigned_to", "follow_up"]].head(500),
        use_container_width=True,
        height=520,
    )

elif PAGE == "Leads":
    page_title("🧩 Leads (Update Status)", "Open one lead and update status, notes, follow-up.")
    if not can(SECTION, "edit", ROLE):
        st.info("Read-only for your role.")

    df = leads_df.drop_duplicates("__hash").copy()
    df["display"] = df["__hash"].astype("string").map(lambda x: disp_map.get(x, x[:6]))
    sel = st.selectbox("Select lead", df["display"].tolist())

    rev = {v: k for k, v in disp_map.items()}
    pid = str(rev.get(sel))
    row = df[df["__hash"].astype("string") == pid].iloc[0].to_dict()

    st.markdown(f"**{pid_to_code.get(pid, pid[:6])} — {row.get('Property Name','')}**")
    st.caption(row.get("Property Address", ""))

    c1, c2 = st.columns(2)
    with c1:
        status = st.selectbox("Status", LEAD_STATUS, index=LEAD_STATUS.index(row.get("status", "New")) if row.get("status", "New") in LEAD_STATUS else 0)
        assigned = st.text_input("Assigned to", value=row.get("assigned_to", ""))
    with c2:
        outcome = st.selectbox("Last call outcome (optional)", [""] + CALL_OUTCOMES, index=0)
        follow = st.text_input("Follow-up (date/note)", value=row.get("follow_up", ""))
    notes = st.text_area("Notes", value=row.get("notes", ""), height=120)

    if st.button("✅ Save Update", type="primary", disabled=not can(SECTION, "edit", ROLE)):
        upsert_lead_update(SECTION, pid, status, assigned, row.get("lead_source") or "Cold Call", notes, follow, outcome or None)
        audit(USER, "LEAD_UPDATE", f"section={SECTION} pid={pid_to_code.get(pid,pid[:6])} status={status}")
        st.success("Saved.")
        st.cache_data.clear()
        st.rerun()

elif PAGE == "Inventory":
    if SECTION != SECTION_INSTALL:
        st.error("Inventory is only for Installation module.")
        st.stop()

    page_title("🗂 Inventory (Sites)", "Save installed site info.")
    base = leads_df.drop_duplicates("__hash").copy()
    base["display"] = base["__hash"].astype("string").map(lambda x: disp_map.get(x, x[:6]))
    sel = st.selectbox("Select property", base["display"].tolist())
    rev = {v: k for k, v in disp_map.items()}
    pid = str(rev.get(sel))
    lead = base[base["__hash"].astype("string") == pid].iloc[0].to_dict()

    ex = qdf("SELECT * FROM inventory_sites_v8 WHERE property_id=:p", {"p": pid})
    ex = ex.iloc[0].to_dict() if len(ex) else {}

    with st.form("inv_form"):
        c1, c2, c3 = st.columns(3)
        with c1:
            date_of_contract = st.text_input("Date of contract (YYYY-MM-DD)", value=ex.get("date_of_contract", ""))
            contract_period = st.text_input("Contract period", value=ex.get("contract_period", ""))
        with c2:
            screen_installed_date = st.text_input("Screen installed date (YYYY-MM-DD)", value=ex.get("screen_installed_date", ""))
            site_rating = st.selectbox("Site rating", [1, 2, 3, 4, 5], index=max(0, int(ex.get("site_rating") or 3) - 1))
        with c3:
            chairman = st.text_input("Chairman name", value=ex.get("chairman_name", ""))
            contact_person = st.text_input("Contact person", value=ex.get("contact_person", ""))
            contact_details = st.text_input("Contact details", value=ex.get("contact_details", ""))

        lat = st.text_input("Latitude", value=str(ex.get("latitude") or ""))
        lon = st.text_input("Longitude", value=str(ex.get("longitude") or ""))
        rent = st.number_input("Agreed rent per month (₹)", min_value=0.0, value=float(ex.get("agreed_rent_pm") or 0.0))
        notes = st.text_area("Notes", value=ex.get("notes", ""), height=100)
        ok = st.form_submit_button("Save", type="primary", disabled=not can(SECTION_INSTALL, "edit", ROLE))

    if ok:
        exec_sql("""
        INSERT INTO inventory_sites_v8(
          property_id, property_code, district, city, property_name, property_address,
          latitude, longitude, date_of_contract, contract_period, screen_installed_date,
          site_rating, chairman_name, contact_person, contact_details, agreed_rent_pm, notes, last_updated
        )
        VALUES(:pid,:pc,:d,:c,:pn,:pa,:lat,:lon,:doc,:cp,:sid,:sr,:ch,:pp,:cd,:rent,:notes,NOW())
        ON CONFLICT(property_id) DO UPDATE SET
          latitude=EXCLUDED.latitude, longitude=EXCLUDED.longitude,
          date_of_contract=EXCLUDED.date_of_contract, contract_period=EXCLUDED.contract_period,
          screen_installed_date=EXCLUDED.screen_installed_date,
          site_rating=EXCLUDED.site_rating, chairman_name=EXCLUDED.chairman_name,
          contact_person=EXCLUDED.contact_person, contact_details=EXCLUDED.contact_details,
          agreed_rent_pm=EXCLUDED.agreed_rent_pm, notes=EXCLUDED.notes, last_updated=NOW()
        """, {
            "pid": pid,
            "pc": pid_to_code.get(pid, pid[:6].upper()),
            "d": lead.get("District", ""),
            "c": lead.get("City", ""),
            "pn": lead.get("Property Name", ""),
            "pa": lead.get("Property Address", ""),
            "lat": float(lat) if str(lat).strip() else None,
            "lon": float(lon) if str(lon).strip() else None,
            "doc": date_of_contract,
            "cp": contract_period,
            "sid": screen_installed_date,
            "sr": int(site_rating),
            "ch": chairman,
            "pp": contact_person,
            "cd": contact_details,
            "rent": float(rent),
            "notes": notes,
        })
        audit(USER, "INVENTORY_SAVE", pid_to_code.get(pid, pid[:6]))
        st.success("Saved.")
        st.rerun()

    st.markdown("### Current record")
    st.dataframe(pd.DataFrame([ex]) if ex else pd.DataFrame(), use_container_width=True)

elif PAGE == "Screens":
    if SECTION != SECTION_INSTALL:
        st.error("Screens is only for Installation module.")
        st.stop()

    page_title("🖥 Screens", "Add screens for each site.")
    inv = qdf("SELECT property_id, property_name FROM inventory_sites_v8 ORDER BY last_updated DESC")
    if len(inv) == 0:
        st.info("Create Inventory record first.")
        st.stop()

    inv["display"] = inv["property_id"].astype("string").map(lambda x: disp_map.get(x, x[:6]))
    sel = st.selectbox("Select site", inv["display"].tolist())
    rev = {v: k for k, v in disp_map.items()}
    pid = str(rev.get(sel))

    with st.form("screen_form"):
        sid = st.text_input("Screen ID *")
        loc = st.text_input("Screen location")
        installed_date = st.text_input("Installed date (YYYY-MM-DD)", value=str(date.today()))
        next_due = st.text_input("Next service due (YYYY-MM-DD)", value=str(date.today() + timedelta(days=30)))
        ok = st.form_submit_button("Save screen", type="primary", disabled=not can(SECTION_INSTALL, "add", ROLE))

    if ok:
        if not sid.strip():
            st.error("Screen ID required.")
        else:
            exec_sql("""
            INSERT INTO screens_v8(screen_id,property_id,screen_location,installed_date,installed_by,next_service_due,is_active,last_updated)
            VALUES(:sid,:pid,:loc,:idate,:iby,:nd,1,NOW())
            ON CONFLICT(screen_id) DO UPDATE SET
              property_id=EXCLUDED.property_id,
              screen_location=EXCLUDED.screen_location,
              installed_date=EXCLUDED.installed_date,
              installed_by=EXCLUDED.installed_by,
              next_service_due=EXCLUDED.next_service_due,
              is_active=1,
              last_updated=NOW()
            """, {"sid": sid.strip(), "pid": pid, "loc": loc, "idate": installed_date, "iby": USER, "nd": next_due})
            audit(USER, "SCREEN_SAVE", sid.strip())
            st.success("Saved.")
            st.rerun()

    scr = qdf("SELECT * FROM screens_v8 WHERE property_id=:p AND is_active=1 ORDER BY last_updated DESC", {"p": pid})
    st.dataframe(scr, use_container_width=True, height=520)

elif PAGE == "Service Center":
    if SECTION != SECTION_INSTALL:
        st.error("Service Center is only for Installation module.")
        st.stop()

    page_title("🛠 Service Center", "Overdue and due this week.")
    scr = qdf("SELECT * FROM screens_v8 WHERE is_active=1")
    if len(scr) == 0:
        st.info("No screens.")
        st.stop()

    scr = scr.copy()
    scr["due_dt"] = pd.to_datetime(scr["next_service_due"], errors="coerce")
    today_dt = pd.to_datetime(date.today())

    overdue = scr[scr["due_dt"].notna() & (scr["due_dt"] < today_dt)]
    due_week = scr[scr["due_dt"].notna() & (scr["due_dt"] >= today_dt) & (scr["due_dt"] <= today_dt + pd.Timedelta(days=7))]

    a, b = st.columns(2)
    with a:
        kpi("Overdue", len(overdue))
    with b:
        kpi("Due 7 days", len(due_week))

    st.markdown("### Overdue")
    st.dataframe(overdue.drop(columns=["due_dt"]), use_container_width=True, height=250)
    st.markdown("### Due in 7 days")
    st.dataframe(due_week.drop(columns=["due_dt"]), use_container_width=True, height=250)

    if can(SECTION_INSTALL, "edit", ROLE):
        st.markdown("### Mark Serviced")
        sid = st.selectbox("Screen ID", scr["screen_id"].astype("string").tolist())
        last = st.text_input("Last service date (YYYY-MM-DD)", value=str(date.today()))
        next_due = st.text_input("Next due date (YYYY-MM-DD)", value=str(date.today() + timedelta(days=30)))
        if st.button("Mark serviced", type="primary"):
            exec_sql("UPDATE screens_v8 SET last_service_date=:ls, next_service_due=:nd, last_updated=NOW() WHERE screen_id=:sid",
                     {"ls": last, "nd": next_due, "sid": sid})
            audit(USER, "SERVICE_MARK", sid)
            st.success("Updated.")
            st.rerun()

elif PAGE == "Documents":
    page_title("📄 Documents", "Upload and track documents (Installation).")
    if SECTION != SECTION_INSTALL:
        st.info("Documents page is enabled for Installation module in this build.")
        st.stop()

    inv = qdf("SELECT property_id FROM inventory_sites_v8 ORDER BY last_updated DESC")
    if len(inv) == 0:
        st.info("Create Inventory record first.")
        st.stop()

    inv["display"] = inv["property_id"].astype("string").map(lambda x: disp_map.get(x, x[:6]))
    sel = st.selectbox("Select site", inv["display"].tolist())
    rev = {v: k for k, v in disp_map.items()}
    pid = str(rev.get(sel))
    pcode = pid_to_code.get(pid, pid[:6])

    d_type = st.selectbox("Doc type", DOC_TYPES_INSTALL)
    file = st.file_uploader("Upload (pdf/jpg/png)", type=["pdf", "jpg", "jpeg", "png"])

    if st.button("Upload", type="primary", disabled=not can(SECTION_INSTALL, "add", ROLE)):
        if not file:
            st.error("Upload a file.")
        else:
            ext = file.name.split(".")[-1].lower()
            fname = f"{pcode}_install_{uuid.uuid4().hex}.{ext}"
            path = os.path.join(UPLOAD_INSTALL, fname)
            with open(path, "wb") as fp:
                fp.write(file.getbuffer())
            st.success("Uploaded (saved to app storage).")

    st.caption("If you want documents to be stored in Supabase Storage later, tell me.")

elif PAGE == "Proposals":
    page_title("📄 Proposals", "Generate proposal PDF (Cloud-safe).")

    settings = get_company_settings()
    signer = get_user_profile(USER) | {"username": USER}

    base = leads_df.drop_duplicates("__hash").copy()
    base["display"] = base["__hash"].astype("string").map(lambda x: disp_map.get(x, x[:6]))
    sel = st.selectbox("Select property", base["display"].tolist())

    rev = {v: k for k, v in disp_map.items()}
    pid = str(rev.get(sel))
    lead = base[base["__hash"].astype("string") == pid].iloc[0].to_dict()

    inv = qdf("SELECT * FROM inventory_sites_v8 WHERE property_id=:p", {"p": pid})
    invr = inv.iloc[0].to_dict() if len(inv) else {}

    rent = float(invr.get("agreed_rent_pm") or 0)

    if st.button("Generate Installation Proposal PDF", type="primary", disabled=not can(SECTION_INSTALL, "add", ROLE)):
        data = {
            "proposal_no": next_proposal_no(),
            "property_name": lead.get("Property Name", ""),
            "property_address": lead.get("Property Address", ""),
            "district": lead.get("District", ""),
            "city": lead.get("City", ""),
            "contact_person": invr.get("contact_person", "") or lead.get("Promoter / Developer Name", ""),
            "contact_phone": invr.get("contact_details", "") or lead.get("Promoter Mobile Number", ""),
            "contact_email": lead.get("Promoter Email", ""),
            "scope_points": [
                "Site survey and feasibility confirmation",
                "Installation of LED display screens as per agreed quantity",
                "Basic maintenance support as per service schedule",
            ],
            "pricing_rows": [{"item": "Agreed Rent (per month)", "amount": f"{rent:,.0f}" if rent else "", "notes": invr.get("contract_period", "")}],
            "timeline_points": ["Installation within 7–15 working days after approvals"],
            "payment_terms": ["Monthly rent payable in advance", "GST applicable as per rules"],
        }

        pdf = make_proposal_pdf_bytes(SECTION_INSTALL, data, settings, signer)
        saved = save_proposal_pdf(SECTION_INSTALL, pid, None, pdf, USER)

        st.success(f"Generated Proposal No {saved['proposal_no']}")
        st.download_button(
            "⬇️ Download PDF",
            data=pdf,
            file_name=f"Installation_Proposal_{saved['proposal_no']}.pdf",
            mime="application/pdf",
            use_container_width=True,
        )

    st.markdown("---")
    hist = qdf("SELECT section, proposal_no, property_id, pdf_filename, created_by, created_at, status FROM proposals_v8 ORDER BY created_at DESC LIMIT 200")
    st.dataframe(hist, use_container_width=True, height=420)

elif PAGE == "WhatsApp":
    page_title("💬 WhatsApp (Click-to-chat)", "Click-to-chat + limit per hour.")

    settings = get_company_settings()
    limit_per_hour = int(settings.get("whatsapp_limit_per_hour") or 50)
    ok_rate = whatsapp_rate_ok(USER, limit_per_hour)
    if not ok_rate:
        st.warning("You reached the WhatsApp limit in the last hour.")

    msg_tpl = st.text_area(
        "Message template",
        value="Hello {contact_person}, this is The Adbook Outdoor. We’d like to discuss {section} opportunity for {property_name} in {city}, {district}.",
        height=90,
    )

    df = leads_df.drop_duplicates("__hash").copy().head(200)
    df["display"] = df["__hash"].astype("string").map(lambda x: disp_map.get(x, x[:6]))
    sel = st.selectbox("Select lead", df["display"].tolist())

    rev = {v: k for k, v in disp_map.items()}
    pid = str(rev.get(sel))
    r = df[df["__hash"].astype("string") == pid].iloc[0].to_dict()

    phone = r.get("Promoter Mobile Number", "")
    contact = r.get("Promoter / Developer Name", "") or "Sir/Madam"
    msg = msg_tpl.format(
        section=SECTION,
        property_name=r.get("Property Name", ""),
        city=r.get("City", ""),
        district=r.get("District", ""),
        contact_person=contact,
    )

    st.link_button(
        "Open WhatsApp",
        whatsapp_url(phone, msg),
        use_container_width=True,
        disabled=(not ok_rate) or (not bool(normalize_mobile(phone))),
    )

elif PAGE == "Reports":
    page_title("📊 Reports", "Latest lead updates.")
    upd = qdf("SELECT * FROM lead_updates_v8 WHERE section=:s ORDER BY last_updated DESC LIMIT 2000", {"s": SECTION})
    st.dataframe(upd, use_container_width=True, height=520)

elif PAGE == "Admin Panel":
    if ROLE != ROLE_SUPERADMIN:
        st.error("Not allowed.")
        st.stop()

    page_title("⚙ Admin Panel", "Create users, reset passwords, company settings.")
    tabs = st.tabs(["Users", "Company Settings", "Audit Logs"])

    with tabs[0]:
        users = qdf("SELECT username, role, section_scope, is_active, last_login_at, created_at FROM users ORDER BY created_at DESC")
        st.dataframe(users, use_container_width=True, height=260)

        st.markdown("### Create/Update user")
        with st.form("create_user"):
            u = st.text_input("Username *")
            role = st.selectbox("Role", list(ROLE_LABEL.keys()))
            scope = st.selectbox("Scope", [SCOPE_BOTH, SECTION_INSTALL, SECTION_ADS])
            pwd = st.text_input("Temporary password *", type="password")
            ok = st.form_submit_button("Save user", type="primary")

        if ok:
            if not u.strip() or not pwd:
                st.error("Username and password required.")
            else:
                exec_sql("""
                INSERT INTO users(username,password_hash,role,section_scope,is_active)
                VALUES(:u,:p,:r,:s,1)
                ON CONFLICT(username) DO UPDATE SET
                  password_hash=EXCLUDED.password_hash,
                  role=EXCLUDED.role,
                  section_scope=EXCLUDED.section_scope,
                  is_active=1,
                  updated_at=NOW()
                """, {"u": u.strip(), "p": pbkdf2_hash(pwd), "r": role, "s": scope})
                audit(USER, "CREATE_USER", f"{u.strip()} role={role} scope={scope}")
                st.success("Saved.")
                st.rerun()

    with tabs[1]:
        st.markdown("### Company Settings")
        settings = get_company_settings()
        gst = st.text_input("GST", value=settings.get("gst_no", ""))
        bank = st.text_area("Bank details (shown in proposal)", value=settings.get("bank_details", ""), height=120)
        limit = st.number_input("WhatsApp limit per hour", min_value=5, max_value=500, value=int(settings.get("whatsapp_limit_per_hour") or 50))
        if st.button("Save settings", type="primary"):
            upsert_company_settings(gst, bank, int(limit))
            audit(USER, "COMPANY_SETTINGS_SAVE", f"gst={gst} limit={limit}")
            st.success("Saved.")
            st.rerun()

    with tabs[2]:
        logs = qdf("SELECT * FROM audit_logs ORDER BY created_at DESC LIMIT 500")
        st.dataframe(logs, use_container_width=True, height=520)


# =============================================================================
# FIRST-TIME SUPERADMIN INSTRUCTIONS
# =============================================================================
st.sidebar.markdown("---")
st.sidebar.markdown("### First-time setup (if no users)")
st.sidebar.caption("Run this in Supabase SQL Editor to create first SuperAdmin (replace password):")
st.sidebar.code(
    "INSERT INTO users(username,password_hash,role,section_scope,is_active)\n"
    "VALUES('admin','" + pbkdf2_hash("ChangeMe123") + "','SuperAdmin','Both',1);\n",
    language="sql",
)
st.sidebar.caption("Then login with: admin / ChangeMe123 (change it later).")
