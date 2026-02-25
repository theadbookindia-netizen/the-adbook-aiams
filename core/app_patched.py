import streamlit as st
import pandas as pd
from datetime import date, datetime, timedelta

from core import runtime as rt

# Keep page config consistent (legacy runtime also sets it; calling again is fine)
try:
    st.set_page_config(page_title="AIAMS", layout="wide")
except Exception:
    pass

# =========================================================
# SINGLE-FILE MENUS + ROUTERS + NEW PAGES
# (Replaces missing modules.install/* and modules.ads/* imports)
# =========================================================

MENU_INSTALL = [
    "📊 Management Dashboard",
    "🏗️ Installation Opportunities",
    "🗺️ Map View",
    "✅ Tasks & Alerts",
    "📈 Reports",
]

MENU_ADS = [
    "📊 Management Dashboard",
    "📣 Ads Opportunities",
    "🗺️ Map View",
    "✅ Tasks & Alerts",
    "📈 Reports",
]

MIGRATION_SQL = """create extension if not exists pgcrypto;

create table if not exists lead_interactions (
  id uuid primary key default gen_random_uuid(),
  section text not null default 'INSTALL',
  entity_table text not null default 'inventory_sites',
  entity_id text not null,
  interaction_date timestamptz not null default now(),
  mode text not null,
  remarks text,
  next_follow_up_date date,
  attachment_url text,
  created_by text,
  created_at timestamptz not null default now()
);

create index if not exists idx_lead_interactions_entity
  on lead_interactions(entity_table, entity_id);

create index if not exists idx_lead_interactions_followup
  on lead_interactions(next_follow_up_date);

create table if not exists tasks_alerts (
  id uuid primary key default gen_random_uuid(),
  section text not null default 'INSTALL',
  title text not null,
  description text,
  severity text not null default 'info',
  due_date date,
  owner_user text,
  status text not null default 'open',
  entity_table text,
  entity_id text,
  rule_key text,
  created_by text,
  created_at timestamptz not null default now(),
  updated_at timestamptz
);

create index if not exists idx_tasks_alerts_owner_status
  on tasks_alerts(owner_user, status);

create index if not exists idx_tasks_alerts_due
  on tasks_alerts(due_date);

create table if not exists weekly_reports (
  id uuid primary key default gen_random_uuid(),
  section text not null default 'INSTALL',
  week_start date not null,
  week_end date not null,
  generated_by text,
  report_json jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

create unique index if not exists uq_weekly_reports_section_week
  on weekly_reports(section, week_start, week_end);
"""


def _strip_menu_emoji(label: str) -> str:
    if hasattr(rt, "page_key_from_label"):
        return rt.page_key_from_label(label)
    if hasattr(rt, "strip_menu_emoji"):
        return rt.strip_menu_emoji(label)
    # fallback
    return label.split(" ", 1)[-1].strip()


def _df(x) -> pd.DataFrame:
    return x if isinstance(x, pd.DataFrame) else pd.DataFrame()


def _try_call(name: str, *args, **kwargs):
    fn = getattr(rt, name, None)
    if callable(fn):
        return fn(*args, **kwargs)
    return None


def _is_viewer(role: str) -> bool:
    r = str(role or "").upper()
    return "VIEWER" in r


# -------------------------
# PAGES (skeleton but functional)
# -------------------------
def page_management_dashboard(section: str):
    st.subheader("Management Dashboard")

    inv = _df(_try_call("list_inventory_sites", section) or _try_call("load_inventory_sites", section))
    scr = _df(_try_call("list_screens", section) or _try_call("load_screens", section))
    pay = _df(_try_call("list_payments", section) or _try_call("load_payments", section))

    total_props = len(inv) if not inv.empty else "—"
    total_screens = len(scr) if not scr.empty else "—"

    contacted = pending = installed = "—"
    if not inv.empty:
        status_col = next((c for c in ["status", "lead_status", "Status"] if c in inv.columns), None)
        if status_col:
            s = inv[status_col].astype("string").fillna("").str.lower()
            contacted = int((s == "contacted").sum())
            installed = int((s == "installed").sum())
            pending = int(s.isin(["new", "follow-up required", "followup required", "follow-up"]).sum())

    conv = "—"
    try:
        if isinstance(contacted, int) and contacted > 0 and isinstance(installed, int):
            conv = f"{(installed/contacted)*100:.1f}%"
    except Exception:
        pass

    c1, c2, c3, c4, c5, c6 = st.columns(6)
    c1.metric("Total Properties", total_props)
    c2.metric("Total Screens", total_screens)
    c3.metric("Leads Contacted", contacted)
    c4.metric("Leads Pending", pending)
    c5.metric("Installed", installed)
    c6.metric("Conversion %", conv)

    st.markdown("#### District-wise Property Count")
    if not inv.empty:
        dcol = next((c for c in ["district", "District"] if c in inv.columns), None)
        if dcol:
            g = inv.groupby(inv[dcol].astype("string").fillna("Unknown")).size().reset_index(name="count")
            g = g.sort_values("count", ascending=False)
            st.dataframe(g, use_container_width=True)
        else:
            st.info("Add inventory_sites.district to enable district drilldown.")
    else:
        st.info("Inventory not loaded (runtime loader not found or empty).")

    st.markdown("#### Revenue Summary (Expected vs Actual)")
    if not pay.empty:
        exp_col = next((c for c in ["expected_amount", "expected", "Expected Amount"] if c in pay.columns), None)
        act_col = next((c for c in ["actual_amount", "actual", "Actual Amount", "amount"] if c in pay.columns), None)
        expected = float(pd.to_numeric(pay[exp_col], errors="coerce").fillna(0).sum()) if exp_col else None
        actual = float(pd.to_numeric(pay[act_col], errors="coerce").fillna(0).sum()) if act_col else None
        r1, r2 = st.columns(2)
        r1.metric("Expected (₹)", f"{expected:,.0f}" if expected is not None else "—")
        r2.metric("Actual (₹)", f"{actual:,.0f}" if actual is not None else "—")
    else:
        st.info("Payments not loaded (runtime loader not found or empty).")


def page_installation_opportunities():
    st.subheader("Installation Opportunities")

    inv = _df(_try_call("list_inventory_sites", rt.SECTION) or _try_call("load_inventory_sites", rt.SECTION))
    if inv.empty:
        st.warning("No inventory data loaded (runtime loader not found or empty).")
        return

    with st.expander("🔎 Advanced Filters", expanded=True):
        c1, c2, c3, c4 = st.columns(4)
        q = c1.text_input("Search (Name/Developer/District/City)", "")
        status = c2.selectbox("Status", ["All","New","Contacted","Follow-up Required","Interested","Installed","Rejected"])
        district = c3.text_input("District", "")
        city = c4.text_input("City", "")

        c5, c6, c7 = st.columns(3)
        min_cr = c5.number_input("Min Cost (₹ Cr)", min_value=0.0, value=0.0, step=0.1)
        max_cr = c6.number_input("Max Cost (₹ Cr)", min_value=0.0, value=0.0, step=0.1)
        near_6m = c7.checkbox("Smart: Near completion (next 6 months)")

        apply_filters = st.button("Apply", type="primary")

    df = inv.copy()
    if apply_filters:
        if q.strip():
            ql = q.strip().lower()
            fields = [c for c in ["property_name","Property Name","developer_name","Developer","district","District","city","City"] if c in df.columns]
            if fields:
                mask = False
                for f in fields:
                    mask = mask | df[f].astype("string").fillna("").str.lower().str.contains(ql, na=False)
                df = df[mask]
        if status != "All":
            scol = next((c for c in ["status","lead_status","Status"] if c in df.columns), None)
            if scol:
                df = df[df[scol].astype("string").fillna("").str.lower() == status.lower()]
        if district.strip():
            dcol = next((c for c in ["district","District"] if c in df.columns), None)
            if dcol:
                df = df[df[dcol].astype("string").fillna("").str.lower().str.contains(district.lower(), na=False)]
        if city.strip():
            ccol = next((c for c in ["city","City"] if c in df.columns), None)
            if ccol:
                df = df[df[ccol].astype("string").fillna("").str.lower().str.contains(city.lower(), na=False)]

        cost_col = next((c for c in ["cost_cr","Cost (Cr)","cost","Property Cost"] if c in df.columns), None)
        if cost_col:
            x = pd.to_numeric(df[cost_col], errors="coerce").fillna(0.0)
            if max_cr > 0:
                df = df[(x >= float(min_cr)) & (x <= float(max_cr))]
            else:
                df = df[x >= float(min_cr)]

        if near_6m:
            dt_col = next((c for c in ["construction_end_date","Construction End Date","end_date"] if c in df.columns), None)
            if dt_col:
                dt = pd.to_datetime(df[dt_col], errors="coerce")
                now = pd.Timestamp.today().normalize()
                df = df[(dt.notna()) & (dt >= now) & (dt <= now + pd.Timedelta(days=183))]

    st.caption(f"Results: {len(df):,} (showing up to 500 rows)")
    st.dataframe(df.head(500), use_container_width=True)

    st.markdown("#### Lead & Contact Management (Next)")
    if _is_viewer(rt.ROLE):
        st.info("Viewer role is read-only.")
    else:
        st.info("Next: Add interaction history (lead_interactions) + status update + audit_logs writes.")


def page_ads_opportunities():
    st.subheader("Ads Opportunities")

    scr = _df(_try_call("list_screens", rt.SECTION) or _try_call("load_screens", rt.SECTION))
    if scr.empty:
        st.warning("No screens data loaded (runtime loader not found or empty).")
        return

    with st.expander("🔎 Filters", expanded=True):
        c1, c2, c3 = st.columns(3)
        q = c1.text_input("Search (Screen/Location)", "")
        avail = c2.selectbox("Availability", ["All","Available","Not Available"])
        city = c3.text_input("City", "")

    df = scr.copy()
    if q.strip():
        ql = q.strip().lower()
        fields = [c for c in ["screen_name","Screen Name","district","District","city","City"] if c in df.columns]
        if fields:
            mask = False
            for f in fields:
                mask = mask | df[f].astype("string").fillna("").str.lower().str.contains(ql, na=False)
            df = df[mask]
    if avail != "All":
        acol = next((c for c in ["is_available","available","Availability"] if c in df.columns), None)
        if acol:
            want = (avail == "Available")
            try:
                df = df[df[acol].fillna(False).astype(bool) == want]
            except Exception:
                pass
    if city.strip():
        ccol = next((c for c in ["city","City"] if c in df.columns), None)
        if ccol:
            df = df[df[ccol].astype("string").fillna("").str.lower().str.contains(city.lower(), na=False)]

    st.caption(f"Results: {len(df):,} (showing up to 500 rows)")
    st.dataframe(df.head(500), use_container_width=True)


def page_map_view(section: str):
    st.subheader("Map View")
    st.info("Next: render clustered map (pydeck) using latitude/longitude from inventory_sites + screens.")


def page_tasks_alerts(section: str):
    st.subheader("Tasks & Alerts")
    st.markdown("#### Migration SQL (copy into Supabase SQL editor)")
    st.code(MIGRATION_SQL, language="sql")
    st.info("Next: generate lead aging + follow-up reminders into tasks_alerts table and show per executive.")


def page_reports(section: str):
    st.subheader("Reports")
    if _is_viewer(rt.ROLE):
        st.warning("Export disabled for Viewer role.")
    else:
        st.success("Export enabled (implement role checks in export handlers too).")
    st.info("Next: executive performance + revenue + white-spot districts + downloads.")


# -------------------------
# ROUTERS
# -------------------------
def route_install(page_key: str):
    if page_key == "Management Dashboard":
        page_management_dashboard(rt.SECTION_INSTALL)
    elif page_key == "Installation Opportunities":
        page_installation_opportunities()
    elif page_key == "Map View":
        page_map_view(rt.SECTION_INSTALL)
    elif page_key == "Tasks & Alerts":
        page_tasks_alerts(rt.SECTION_INSTALL)
    elif page_key == "Reports":
        page_reports(rt.SECTION_INSTALL)
    else:
        st.warning(f"Unknown page: {page_key}")


def route_ads(page_key: str):
    if page_key == "Management Dashboard":
        page_management_dashboard(rt.SECTION_ADS)
    elif page_key == "Ads Opportunities":
        page_ads_opportunities()
    elif page_key == "Map View":
        page_map_view(rt.SECTION_ADS)
    elif page_key == "Tasks & Alerts":
        page_tasks_alerts(rt.SECTION_ADS)
    elif page_key == "Reports":
        page_reports(rt.SECTION_ADS)
    else:
        st.warning(f"Unknown page: {page_key}")


def main():
    # ---- Auth (unchanged) ----
    rt.bootstrap_if_no_users()
    rt.require_auth()

    auth = st.session_state.get("auth", {})
    rt.USER = (auth.get("user") or "").strip()
    rt.ROLE = rt.canonical_role((auth.get("role") or "").upper(), auth.get("scope"))
    rt.SCOPE = (auth.get("scope") or rt.SCOPE_BOTH).title() if hasattr(rt, "SCOPE_BOTH") else (auth.get("scope") or "Both").title()

    # ---- Sidebar (module selector + global search) ----
    with st.sidebar:
        st.markdown("### The Adbook AIAMS")
        st.caption("Outdoor Media Operations System")
        st.markdown("---")
        st.markdown("### AIAMS")
        st.markdown(f"**User:** {rt.USER}")
        st.markdown(f"**Role:** {rt.ROLE_LABEL.get(rt.ROLE, rt.ROLE) if hasattr(rt, 'ROLE_LABEL') else rt.ROLE}")
        st.markdown("---")

        # Data source (kept as legacy behavior)
        data_mode = st.radio("Data Source", ["Bundled (CSV)", "Upload Excel/CSV"], index=0, key="data_mode")
        upload = None
        if data_mode == "Upload Excel/CSV":
            upload = st.file_uploader("Upload file", type=["csv", "xlsx", "xls"], key="lead_upload")
            if not upload:
                st.stop()

        # Persist upload handle in session for downstream reads
        st.session_state["__lead_upload__"] = upload

        allowed_sections = [rt.SECTION_INSTALL, rt.SECTION_ADS] if rt.SCOPE == rt.SCOPE_BOTH else [rt.SCOPE]

        # Role-based default module (UI-only)
        _default_section = rt.SECTION_INSTALL
        if rt.ROLE in [getattr(rt, 'ROLE_ADS_MANAGER', ''), getattr(rt, 'ROLE_ADS_MARKETING', ''), getattr(rt, 'ROLE_ADS_FIELD', ''), getattr(rt, 'ROLE_VIEWER_ADS', '')]:
            _default_section = rt.SECTION_ADS
        if rt.ROLE in [getattr(rt, 'ROLE_INSTALLATION_MANAGER', ''), getattr(rt, 'ROLE_INSTALLATION_MARKETING', ''), getattr(rt, 'ROLE_INSTALLATION_FIELD', ''), getattr(rt, 'ROLE_VIEWER_INSTALLATION', '')]:
            _default_section = rt.SECTION_INSTALL
        if allowed_sections and _default_section not in allowed_sections:
            _default_section = allowed_sections[0]

        rt.SECTION = st.radio(
            "Module",
            allowed_sections,
            horizontal=True,
            index=allowed_sections.index(_default_section) if _default_section in allowed_sections else 0,
            format_func=lambda x: "Module-1: Installation" if x == rt.SECTION_INSTALL else ("Module-2: Advertisements" if x == rt.SECTION_ADS else str(x)),
            key="sidebar_module",
        )

        rt.require_module_access(rt.SECTION)

        # Module-wise menu, filtered by role permissions (UI-only)
        menu = rt.build_menu_for(rt.SECTION, rt.ROLE)
        # Fallback if build_menu_for returns empty
        if not menu:
            menu = MENU_INSTALL if rt.SECTION == rt.SECTION_INSTALL else MENU_ADS

        page_label = st.selectbox("Navigation", menu, key=f"nav_{rt.SECTION}")

        st.markdown("### 🔎 Global Search")
        with st.form("global_search_form", clear_on_submit=False):
            st.text_input("Search across modules", key="global_search_term")
            c1, c2 = st.columns([1,1])
            with c1:
                clear = st.form_submit_button("Clear")
            with c2:
                go = st.form_submit_button("Search", type="primary")
            if clear:
                st.session_state["global_search_term"] = ""
                st.session_state["__global_search_go__"] = False
            if go:
                st.session_state["__global_search_go__"] = True

    # Convert menu label (with emoji) to PAGE_KEY
    rt.PAGE_KEY = _strip_menu_emoji(page_label)

    # ---- Route to module router ----
    if rt.SECTION == rt.SECTION_INSTALL:
        route_install(rt.PAGE_KEY)
    else:
        route_ads(rt.PAGE_KEY)


if __name__ == "__main__":
    main()
