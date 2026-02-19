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
# DATABASE (SUPABASE) — optimized + fixed cache bug
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

    # Small pool, pre_ping for reliability
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
# MIGRATIONS (unchanged tables)
# =========================================================
def migrate() -> None:
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


def seed_permissions_once():
    c = int(qdf("SELECT COUNT(*) AS c FROM permissions").iloc[0]["c"] or 0)
    if c > 0:
        return
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


migrate()
seed_permissions_once()


# =========================================================
# AUTH (PBKDF2) + plain$ support
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
# DATA HELPERS (FAST)
# =========================================================
def normalize_mobile_series(s: pd.Series) -> pd.Series:
    s = s.fillna("").astype(str)
    s = s.str.replace(r"[^0-9+]", "", regex=True).str.replace("+91", "", regex=False)
    s = s.str.replace(r"\D", "", regex=True)
    # last 10 digits if longer
    return s.apply(lambda x: x[-10:] if len(x) > 10 else x)


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


def read_leads_file(upload=None) -> pd.DataFrame:
    if upload is None:
        if not os.path.exists(DATA_FILE):
            st.error(f"Missing {DATA_FILE}. Upload a file OR add {DATA_FILE} next to app.py.")
            st.stop()
        file_bytes = Path(DATA_FILE).read_bytes()
        filename = DATA_FILE.lower()
    else:
        file_bytes = upload.getvalue()
        filename = upload.name.lower()

    if filename.endswith(".csv"):
        df = _read_csv_bytes(file_bytes)
    elif filename.endswith(".xlsx") or filename.endswith(".xls"):
        xl = pd.ExcelFile(io.BytesIO(file_bytes))
        sheet = st.selectbox("Select sheet", xl.sheet_names, key="sheet_picker")
        df = _read_excel_sheet(file_bytes, sheet)
    else:
        st.error("Unsupported file. Please upload CSV or Excel (.xlsx).")
        st.stop()

    df.columns = [str(c).strip() for c in df.columns]

    if "District Type" in df.columns and "City" not in df.columns:
        df = df.rename(columns={"District Type": "City"})

    return df


def _letters2(x) -> str:
    s = "" if x is None else str(x)
    s = s.upper()
    s = re.sub(r"[^A-Za-z]", "", s)
    return (s + "XX")[:2]


@st.cache_data(show_spinner=False, ttl=120)
def get_property_codes_df() -> pd.DataFrame:
    return qdf("SELECT property_id, property_code, district, city, property_name FROM property_codes")


def ensure_property_codes(leads_df: pd.DataFrame, batch_size: int = 700) -> pd.DataFrame:
    """
    Faster: only inserts missing property_ids.
    Uses cached read of property_codes with TTL.
    """
    needed = leads_df[["__hash", "District", "City", "Property Name"]].drop_duplicates().copy()
    needed.columns = ["property_id", "district", "city", "property_name"]

    existing = get_property_codes_df()
    existing_ids = set(existing["property_id"].astype("string").tolist()) if len(existing) else set()

    missing = needed[~needed["property_id"].astype("string").isin(existing_ids)]
    if len(missing) == 0:
        return existing

    # Build used numbers per prefix
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

        # refresh cache
        get_property_codes_df.clear()

    return get_property_codes_df()


def property_display_map(code_df: pd.DataFrame, leads_df: pd.DataFrame) -> dict:
    base = leads_df.drop_duplicates("__hash").set_index("__hash")
    if "Property Name" not in base.columns:
        base["Property Name"] = ""
    if "City" not in base.columns:
        base["City"] = ""

    nm = base["Property Name"].fillna("").astype(str)
    ct = base["City"].fillna("").astype(str)
    name_map = pd.DataFrame({"nm": nm, "ct": ct})

    out = {}
    for pid, code in zip(code_df["property_id"].astype("string"), code_df["property_code"].astype("string")):
        pid = str(pid)
        code = str(code)
        if pid in name_map.index:
            n = name_map.loc[pid, "nm"]
            c = name_map.loc[pid, "ct"]
            label = f"{code} — {n[:45]} — {c}"
        else:
            label = f"{code} — {pid[:6]}"
        out[pid] = label
    return out


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
    list_lead_updates.clear()  # refresh quickly


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

    MENU_INSTALL = ["Home", "Leads", "Inventory", "Screens", "Documents", "Proposals", "WhatsApp", "Reports"]
    MENU_ADS = ["Home", "Leads", "WhatsApp", "Reports"]
    menu = MENU_INSTALL if SECTION == SECTION_INSTALL else MENU_ADS
    if ROLE == ROLE_SUPERADMIN:
        menu = menu + ["Admin Panel"]

    PAGE = st.selectbox("Page", menu)


# =========================================================
# LOAD LEADS (FAST + CACHED) + VECTOR HASH
# =========================================================
leads_df = read_leads_file(upload).copy()

required_cols = [
    "District", "City", "Property Name", "Property Address",
    "Promoter Mobile Number", "Promoter Email", "Promoter / Developer Name"
]
for col in required_cols:
    if col not in leads_df.columns:
        leads_df[col] = ""

# clean strings (vectorized)
for c in required_cols:
    leads_df[c] = leads_df[c].fillna("").astype(str).str.strip()

leads_df["__mobile_norm"] = normalize_mobile_series(leads_df["Promoter Mobile Number"])

# FAST stable hash (vectorized)
hash_cols = pd.DataFrame({
    "pn": leads_df["Property Name"].str.lower(),
    "pa": leads_df["Property Address"].str.lower(),
    "d": leads_df["District"].str.lower(),
    "c": leads_df["City"].str.lower(),
    "m": leads_df["__mobile_norm"],
    "e": leads_df["Promoter Email"].str.lower(),
})
# uint64 hash then hex string (very fast)
h64 = pd.util.hash_pandas_object(hash_cols, index=False)
leads_df["__hash"] = h64.apply(lambda x: f"{int(x) & ((1<<64)-1):016x}")

# Build a single search index column once (fast search)
leads_df["__search"] = (
    leads_df["Property Name"] + " | " +
    leads_df["Property Address"] + " | " +
    leads_df["Promoter / Developer Name"] + " | " +
    leads_df["Promoter Email"] + " | " +
    leads_df["Promoter Mobile Number"] + " | " +
    leads_df["District"] + " | " +
    leads_df["City"]
).str.lower()

# codes (bulk only for missing)
codes_df = ensure_property_codes(leads_df)
disp_map = property_display_map(codes_df, leads_df)
pid_to_code = dict(zip(codes_df["property_id"].astype("string"), codes_df["property_code"].astype("string")))

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
if PAGE == "Home":
    page_title("🏠 Home (Fast Search)", f"{SECTION}: Search properties quickly (optimized).")

    with st.expander("How to use search + filters", expanded=False):
        st.write(
            "• Type any keyword (property / promoter / mobile / email / district / city)\n"
            "• Use pagination to browse results\n"
            "• For updates, open **Leads** page"
        )

    q = st.text_input("Search (Property / Promoter / Phone / Email)", placeholder="Type and press Enter…")
    df = leads_df

    if q.strip():
        s = q.strip().lower()
        # single-column contains = fast
        df = df[df["__search"].str.contains(re.escape(s), na=False)]

    st.markdown(f"<span class='badge badge-strong'>Matches: {len(df):,}</span>", unsafe_allow_html=True)

    # Pagination (huge speed help)
    page_size = st.selectbox("Rows per page", [25, 50, 100, 200, 500], index=2)
    total_pages = max(1, (len(df) + page_size - 1) // page_size)
    page_no = st.number_input("Page", min_value=1, max_value=total_pages, value=1, step=1)

    start = (page_no - 1) * page_size
    end = start + page_size

    view_cols = ["District", "City", "Property Name", "Promoter / Developer Name",
                 "Promoter Mobile Number", "Promoter Email", "status", "assigned_to", "follow_up"]
    dfv = safe_df_cols(df, view_cols).iloc[start:end]

    st.dataframe(dfv, use_container_width=True, height=560)

elif PAGE == "Leads":
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

elif PAGE == "Inventory":
    if SECTION != SECTION_INSTALL:
        st.error("Inventory is only for Installation module.")
        st.stop()

    page_title("🗂 Inventory (Sites)", "Save installed site info.")

    base = leads_df.drop_duplicates("__hash").copy()
    base["display"] = base["__hash"].astype("string").map(lambda x: disp_map.get(str(x), str(x)[:6]))

    if len(base) == 0:
        st.info("No leads available.")
        st.stop()

    sel = st.selectbox("Select property", base["display"].tolist())
    rev = {v: k for k, v in disp_map.items()}
    pid = str(rev.get(sel))
    lead = base[base["__hash"].astype("string") == pid].iloc[0].to_dict()

    ex = qdf("SELECT * FROM inventory_sites WHERE property_id=:p", {"p": pid})
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
        inv_notes = st.text_area("Notes", value=ex.get("notes", ""), height=100)

        ok = st.form_submit_button("Save", type="primary", disabled=not can(SECTION_INSTALL, "edit", ROLE))

    if ok:
        exec_sql(
            """
            INSERT INTO inventory_sites(
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
            """,
            {
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
                "notes": inv_notes,
            },
        )
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
    inv = qdf("SELECT property_id FROM inventory_sites ORDER BY last_updated DESC")
    if len(inv) == 0:
        st.info("Create Inventory record first.")
        st.stop()

    inv["display"] = inv["property_id"].astype("string").map(lambda x: disp_map.get(str(x), str(x)[:6]))
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
            exec_sql(
                """
                INSERT INTO screens(screen_id,property_id,screen_location,installed_date,installed_by,next_service_due,is_active,last_updated)
                VALUES(:sid,:pid,:loc,:idate,:iby,:nd,1,NOW())
                ON CONFLICT(screen_id) DO UPDATE SET
                  property_id=EXCLUDED.property_id,
                  screen_location=EXCLUDED.screen_location,
                  installed_date=EXCLUDED.installed_date,
                  installed_by=EXCLUDED.installed_by,
                  next_service_due=EXCLUDED.next_service_due,
                  is_active=1,
                  last_updated=NOW()
                """,
                {"sid": sid.strip(), "pid": pid, "loc": loc, "idate": installed_date, "iby": USER, "nd": next_due},
            )
            audit(USER, "SCREEN_SAVE", sid.strip())
            st.success("Saved.")
            st.rerun()

    scr = qdf("SELECT * FROM screens WHERE property_id=:p AND is_active=1 ORDER BY last_updated DESC", {"p": pid})
    st.dataframe(scr, use_container_width=True, height=520)

elif PAGE == "Documents":
    if SECTION != SECTION_INSTALL:
        st.info("Documents are enabled for Installation in this build.")
        st.stop()

    page_title("📄 Documents", "Upload and track Installation documents.")
    inv = qdf("SELECT property_id FROM inventory_sites ORDER BY last_updated DESC")
    if len(inv) == 0:
        st.info("Create Inventory record first.")
        st.stop()

    inv["display"] = inv["property_id"].astype("string").map(lambda x: disp_map.get(str(x), str(x)[:6]))
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

            exec_sql(
                """
                INSERT INTO documents_install(doc_id,property_id,doc_type,filename,issue_date,expiry_date,uploaded_by)
                VALUES(:id,:p,:t,:f,:i,:e,:u)
                """,
                {"id": str(uuid.uuid4()), "p": pid, "t": d_type, "f": fname, "i": str(date.today()), "e": "", "u": USER},
            )
            audit(USER, "DOC_UPLOAD_INSTALL", f"{pcode} {d_type}")
            st.success("Uploaded.")
            st.rerun()

    df = qdf("SELECT * FROM documents_install WHERE property_id=:p ORDER BY uploaded_at DESC", {"p": pid})
    st.dataframe(df, use_container_width=True, height=520)

elif PAGE == "Proposals":
    if SECTION != SECTION_INSTALL:
        st.info("Proposals are enabled for Installation in this build.")
        st.stop()

    page_title("📄 Proposals", "Generate proposal PDF (cloud-safe).")
    settings = get_company_settings()
    signer_profile = get_user_profile(USER)
    signer = {"username": USER, "designation": signer_profile.get("designation", "")}

    base = leads_df.drop_duplicates("__hash").copy()
    base["display"] = base["__hash"].astype("string").map(lambda x: disp_map.get(str(x), str(x)[:6]))
    sel = st.selectbox("Select property", base["display"].tolist())
    rev = {v: k for k, v in disp_map.items()}
    pid = str(rev.get(sel))
    lead = base[base["__hash"].astype("string") == pid].iloc[0].to_dict()

    inv = qdf("SELECT * FROM inventory_sites WHERE property_id=:p", {"p": pid})
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
            "payment_terms": ["Monthly rent payable in advance", "GST applicable as per rules"],
        }

        pdf = make_proposal_pdf_bytes(SECTION_INSTALL, data, settings, signer)
        saved = save_proposal_pdf(SECTION_INSTALL, pid, pdf, USER)

        st.success(f"Generated Proposal No {saved['proposal_no']}")
        st.download_button(
            "⬇️ Download PDF",
            data=pdf,
            file_name=f"Installation_Proposal_{saved['proposal_no']}.pdf",
            mime="application/pdf",
            use_container_width=True,
        )

    st.markdown("---")
    hist = qdf("SELECT section, proposal_no, property_id, pdf_filename, created_by, created_at, status FROM proposals ORDER BY created_at DESC LIMIT 200")
    st.dataframe(hist, use_container_width=True, height=420)

elif PAGE == "WhatsApp":
    page_title("💬 WhatsApp (Click-to-chat)", "Open WhatsApp message and log sent.")
    msg_tpl = st.text_area(
        "Message template",
        value="Hello {contact_person}, this is The Adbook Outdoor. We’d like to discuss an opportunity for {property_name} in {city}, {district}.",
        height=90,
    )

    df = leads_df.drop_duplicates("__hash").copy()
    if len(df) == 0:
        st.info("No leads available.")
        st.stop()

    # limit selectable list for UI speed, but keep search ability
    q = st.text_input("Quick filter leads list (optional)", placeholder="Type property / city / promoter…")
    if q.strip():
        df = df[df["__search"].str.contains(re.escape(q.strip().lower()), na=False)]
    df = df.head(500)

    df["display"] = df["__hash"].astype("string").map(lambda x: disp_map.get(str(x), str(x)[:6]))
    sel = st.selectbox("Select lead", df["display"].tolist())
    rev = {v: k for k, v in disp_map.items()}
    pid = str(rev.get(sel))
    r = df[df["__hash"].astype("string") == pid].iloc[0].to_dict()

    phone = r.get("Promoter Mobile Number", "")
    contact = r.get("Promoter / Developer Name", "") or "Sir/Madam"

    msg = msg_tpl.format(
        property_name=r.get("Property Name", ""),
        city=r.get("City", ""),
        district=r.get("District", ""),
        contact_person=contact,
    )

    wa = whatsapp_url(phone, msg)
    st.link_button("Open WhatsApp", wa, use_container_width=True, disabled=(wa == "#"))

    if st.button("Mark Sent ✅", type="primary"):
        exec_sql(
            "INSERT INTO whatsapp_logs(log_id,lead_hash,username,action_status) VALUES(:id,:h,:u,'Sent')",
            {"id": str(uuid.uuid4()), "h": pid, "u": USER},
        )
        audit(USER, "WA_SENT", pid_to_code.get(pid, pid[:6]))
        st.success("Logged.")
        st.rerun()

    st.markdown("---")
    logs = qdf("SELECT * FROM whatsapp_logs ORDER BY created_at DESC LIMIT 200")
    st.dataframe(logs, use_container_width=True, height=380)

elif PAGE == "Reports":
    page_title("📊 Reports", "Latest lead updates.")
    upd = qdf("SELECT * FROM lead_updates WHERE section=:s ORDER BY last_updated DESC LIMIT 3000", {"s": SECTION})
    st.dataframe(upd, use_container_width=True, height=560)

elif PAGE == "Admin Panel":
    if ROLE != ROLE_SUPERADMIN:
        st.error("Not allowed.")
        st.stop()

    page_title("⚙ Admin Panel", "Create users, reset passwords, company settings, audit logs.")
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
            mode = st.selectbox("Password mode", ["Secure (recommended)", "Simple (plain$)"], index=0)
            ok = st.form_submit_button("Save user", type="primary")
        if ok:
            if not u.strip() or not pwd:
                st.error("Username and password required.")
            else:
                ph = pbkdf2_hash(pwd) if mode.startswith("Secure") else "plain$" + pwd
                exec_sql(
                    """
                    INSERT INTO users(username,password_hash,role,section_scope,is_active)
                    VALUES(:u,:p,:r,:s,1)
                    ON CONFLICT(username) DO UPDATE SET
                      password_hash=EXCLUDED.password_hash,
                      role=EXCLUDED.role,
                      section_scope=EXCLUDED.section_scope,
                      is_active=1,
                      updated_at=NOW()
                    """,
                    {"u": u.strip(), "p": ph, "r": role, "s": scope},
                )
                audit(USER, "CREATE_USER", f"{u.strip()} role={role} scope={scope}")
                st.success("Saved.")
                st.rerun()

        st.markdown("### Disable user")
        if len(users):
            sel = st.selectbox("Select user", users["username"].astype("string").tolist())
            if st.button("Disable", type="primary"):
                exec_sql("UPDATE users SET is_active=0, updated_at=NOW() WHERE username=:u", {"u": sel})
                audit(USER, "DISABLE_USER", sel)
                st.success("Disabled.")
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

        st.markdown("---")
        st.markdown("### Signature upload (per user)")
        users_df = qdf("SELECT username FROM users ORDER BY username")
        sel = st.selectbox("User", users_df["username"].astype("string").tolist(), key="sig_user")
        prof = get_user_profile(sel)
        file = st.file_uploader("Signature file (png/jpg)", type=["png", "jpg", "jpeg"])
        if file and st.button("Upload signature", type="primary"):
            ext = file.name.split(".")[-1].lower()
            fname = f"sig_{sel}_{uuid.uuid4().hex}.{ext}"
            path = os.path.join(UPLOAD_SIG, fname)
            with open(path, "wb") as fp:
                fp.write(file.getbuffer())
            update_user_signature(sel, fname)
            audit(USER, "SIGNATURE_UPLOAD", sel)
            st.success("Uploaded.")
            st.rerun()
        st.write("Current:", prof.get("signature_filename", "(none)"))
    with tabs[2]:
        logs = qdf("SELECT * FROM audit_logs ORDER BY created_at DESC LIMIT 500")
        st.dataframe(logs, use_container_width=True, height=560)
