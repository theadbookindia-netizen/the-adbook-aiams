import os
import pandas as pd
from sqlalchemy import create_engine, text

@st.cache_resource
def get_engine():
    db_url = os.environ.get("DATABASE_URL", "")
    if not db_url:
        st.error("DATABASE_URL not found. Add it in Streamlit Cloud → Settings → Secrets.")
        st.stop()
    return create_engine(db_url, pool_pre_ping=True)

engine = get_engine()

def exec_sql(sql, params=None):
    with engine.begin() as conn:
        conn.execute(text(sql), params or {})

def qdf(sql, params=None):
    with engine.connect() as conn:
        return pd.read_sql(text(sql), conn, params=params or {})

# Create a simple table (example: installation leads)
exec_sql("""
CREATE TABLE IF NOT EXISTS inst_leads (
  lead_id TEXT PRIMARY KEY,
  district TEXT,
  city TEXT,
  property_name TEXT,
  contact_person TEXT,
  mobile TEXT,
  email TEXT,
  status TEXT DEFAULT 'New',
  assigned_to TEXT,
  created_at TIMESTAMP DEFAULT NOW()
)
""")

import streamlit as st

st.set_page_config(page_title="AIAMS v9.0", layout="wide")

import os
if os.path.exists("assets/logo.png"):
    st.image("assets/logo.png", width=180)
else:
    st.markdown("### The Adbook AIAMS v9.0")
st.title("The Adbook AIAMS v9.0")

st.caption("Dual Module: Installation & Advertisement (Rebuild)")

menu = st.sidebar.radio("Navigation", [
    "Dashboard",
    "Installation",
    "Advertisement",
    "Admin Panel"
])

if menu == "Dashboard":
    st.subheader("Overview Dashboard")
    st.info("KPIs will appear here.")

elif menu == "Installation":
    sub = st.sidebar.selectbox("Installation Menu", [
        "Leads","Inventory","Screens","Service Center",
        "Agreements","Documents","Reports"
    ])
    st.subheader(f"Installation → {sub}")

elif menu == "Advertisement":
    sub = st.sidebar.selectbox("Advertisement Menu", [
        "Leads","Advertisers","Ad Inventory","Screen Allotment",
        "Agreements","Billing","Documents","Reports"
    ])
    st.subheader(f"Advertisement → {sub}")

elif menu == "Admin Panel":
    sub = st.sidebar.selectbox("Admin Menu", [
        "Users","Permissions Matrix","Round Robin Rules","System Settings"
    ])
    st.subheader(f"Admin → {sub}")

st.markdown("---")
st.caption("AIAMS v9.0 – Clean Architecture Scaffold")
