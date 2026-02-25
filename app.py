import streamlit as st
from sqlalchemy import text
import pandas as pd
import uuid
from datetime import date

from core import runtime as rt
from modules.install.menu import MENU_INSTALL
from modules.ads.menu import MENU_ADS
from modules.install.router import route_install
from modules.ads.router import route_ads

# Keep page config consistent (legacy runtime also sets it; calling again is fine)
try:
    st.set_page_config(page_title="AIAMS", layout="wide")
except Exception:
    pass


# =========================================================
# WORKFLOW (STAGE-BASED) DEFINITIONS
# =========================================================
INSTALL_STAGES = [
    (0, "Stage 0 — Property Targeting", "Office Marketing"),
    (1, "Stage 1 — Lead Follow-up", "Office Marketing"),
    (2, "Stage 2 — Site Survey", "Field Marketing"),
    (3, "Stage 3 — Owner Proposal", "Field Marketing"),
    (4, "Stage 4 — Agreement & Onboarding", "Admin/Field"),
    (5, "Stage 5 — Installation", "Installation Team"),
    (6, "Stage 6 — Maintenance & Service", "Installation Team"),
    (7, "Stage 7 — Billing & Collections", "Accounts"),
]

ADS_STAGES = [
    (0, "Stage 0 — Inventory Planning", "Marketing Head"),
    (1, "Stage 1 — Advertiser Lead", "Office Sales"),
    (2, "Stage 2 — Qualification", "Sales Executive"),
    (3, "Stage 3 — Proposal & Quotation", "Corporate Sales"),
    (4, "Stage 4 — Booking (Date Lock)", "Management/Sales"),
    (5, "Stage 5 — Advertising Agreement", "Admin"),
    (6, "Stage 6 — Campaign Deployment", "Operations"),
    (7, "Stage 7 — Monitoring & Issues", "Support"),
    (8, "Stage 8 — Billing & Collections", "Accounts"),
    (9, "Stage 9 — Reporting & Renewal", "Account Manager"),
]

def _stage_list_for(section: str):
    return INSTALL_STAGES if section == getattr(rt, "SECTION_INSTALL", "Installation") else ADS_STAGES

def _stage_label(section: str, stage_no: int) -> str:
    for s, lbl, _team in _stage_list_for(section):
        if s == stage_no:
            return lbl
    return f"Stage {stage_no}"

def _get_engine():
    # Try common runtime patterns without breaking existing app
    eng = None
    try:
        if hasattr(rt, "db_engine"):
            eng = rt.db_engine()
        elif hasattr(rt, "ENGINE"):
            eng = rt.ENGINE
        elif hasattr(rt, "engine"):
            eng = rt.engine
    except Exception:
        eng = None
    return eng

def _get_current_stage(conn, record_hash: str, section: str) -> int:
    q = """
    SELECT COALESCE(current_stage, 0) AS current_stage
    FROM lead_updates
    WHERE record_hash=:h AND section=:s
    ORDER BY created_at DESC
    LIMIT 1
    """
    row = conn.execute(text(q), {"h": record_hash, "s": section}).mappings().first()
    return int(row["current_stage"]) if row else 0

def _set_stage(conn, record_hash: str, section: str, stage_no: int):
    q = """
    UPDATE lead_updates
    SET current_stage=:st,
        stage_label=:lbl,
        stage_updated_at=NOW()
    WHERE record_hash=:h AND section=:s
    """
    conn.execute(text(q), {
        "st": int(stage_no),
        "lbl": _stage_label(section, int(stage_no)),
        "h": record_hash,
        "s": section
    })

def _ads_conflicts(conn, screen_ids, start_d: date, end_d: date):
    if not screen_ids:
        return []
    q = """
    SELECT DISTINCT screen_id
    FROM ad_campaign_screens
    WHERE screen_id = ANY(:screens)
      AND start_date IS NOT NULL AND end_date IS NOT NULL
      AND (start_date <= :end_d AND end_date >= :start_d)
    """
    rows = conn.execute(text(q), {"screens": list(screen_ids), "start_d": start_d, "end_d": end_d}).mappings().all()
    return [r["screen_id"] for r in rows]

def _ads_block_screens(conn, campaign_id: str, screen_ids, start_d: date, end_d: date):
    q = """
    INSERT INTO ad_campaign_screens (id, campaign_id, screen_id, slot_name, schedule_text, start_date, end_date)
    VALUES (:id, :cid, :sid, :slot, :sched, :sd, :ed)
    """
    for sid in screen_ids:
        conn.execute(text(q), {
            "id": f"ACS_{campaign_id}_{sid}",
            "cid": campaign_id,
            "sid": sid,
            "slot": "default",
            "sched": "",
            "sd": start_d,
            "ed": end_d
        })

def _render_workflow(section: str):
    st.title("✅ Workflow (Stages)")
    st.caption("This is the new stage-based workflow. Your existing menus/pages remain unchanged.")

    eng = _get_engine()
    if eng is None:
        st.error("Database engine not available from runtime. Please confirm core/runtime exposes db_engine().")
        return

    stages = _stage_list_for(section)
    stage_options = {f"{s} — {lbl}  ({team})": s for s, lbl, team in stages}
    selected_key = st.selectbox("Open Stage", list(stage_options.keys()))
    selected_stage = stage_options[selected_key]

    # Choose a record (Installation uses record_hash from lead_updates; Ads uses advertiser_leads/booking)
    with eng.begin() as conn:
        if section == getattr(rt, "SECTION_INSTALL", "Installation"):
            st.subheader("Installation Lead")
            leads = conn.execute(text("""
                SELECT record_hash, COALESCE(lead_name,'') AS lead_name, COALESCE(status,'') AS status
                FROM lead_updates
                WHERE section=:s
                ORDER BY created_at DESC
                LIMIT 200
            """), {"s": section}).mappings().all()
            lead_map = {f"{(r['lead_name'] or r['record_hash'])}  | {r['status']}": r["record_hash"] for r in leads} if leads else {}
            record_hash = st.selectbox("Select Lead (record_hash)", list(lead_map.keys())) if lead_map else None
            if record_hash:
                record_hash = lead_map[record_hash]
            else:
                record_hash = st.text_input("Or enter record_hash manually")

            if not record_hash:
                st.info("Select a lead to view and move stages.")
                return

            current_stage = _get_current_stage(conn, record_hash, section)
            st.write(f"**Current Stage:** {current_stage} — {_stage_label(section, current_stage)}")

            editable = (selected_stage == current_stage)
            if selected_stage > current_stage:
                st.warning("This stage is locked. Complete earlier stages first.")
            st.divider()

            # Minimal per-stage placeholders (keeps old system intact)
            if selected_stage == 0:
                st.markdown("### Stage 0 — Property Targeting")
                st.write("Use your existing **Property/Inventory** pages for full details. This stage view is for tracking + handover.")
            elif selected_stage == 1:
                st.markdown("### Stage 1 — Lead Follow-up")
                st.write("Use existing **Leads Pipeline / Follow-ups** pages for calling, WhatsApp logs, and tasks.")
            elif selected_stage == 2:
                st.markdown("### Stage 2 — Site Survey")
                st.write("Use existing **Survey** page (if present) to capture feasibility and photos.")
            elif selected_stage == 3:
                st.markdown("### Stage 3 — Owner Proposal")
                st.write("Use existing **Agreement/Proposal** area to save proposal terms (rent/rev share/tenure).")
            elif selected_stage == 4:
                st.markdown("### Stage 4 — Agreement")
                st.write("Use existing **Agreements** page to create signed agreement + upload KYC.")
            elif selected_stage == 5:
                st.markdown("### Stage 5 — Installation")
                st.write("Use existing **Workorders/Screens** pages to register installation + commissioning.")
            elif selected_stage == 6:
                st.markdown("### Stage 6 — Maintenance")
                st.write("Use **Service Tickets / Screens Service** pages to track issues and next service due.")
            elif selected_stage == 7:
                st.markdown("### Stage 7 — Billing")
                st.write("Use existing **Payments** page to record due/paid and view aging.")

            c1, c2 = st.columns([1, 1])
            with c1:
                if st.button("✅ Mark Stage Complete → Next Stage", disabled=not editable, type="primary"):
                    max_stage = max(s for s, _, _ in stages)
                    next_stage = min(current_stage + 1, max_stage)
                    _set_stage(conn, record_hash, section, next_stage)
                    st.success(f"Moved to {next_stage} — {_stage_label(section, next_stage)}")
                    st.rerun()
            with c2:
                if st.button("⏪ Move Back One Stage", disabled=not editable or current_stage == 0):
                    prev_stage = max(0, current_stage - 1)
                    _set_stage(conn, record_hash, section, prev_stage)
                    st.success(f"Moved back to {prev_stage} — {_stage_label(section, prev_stage)}")
                    st.rerun()

        else:
            # Advertisement workflow: focus on Stage 4 booking with date-lock
            st.subheader("Advertisement Workflow")
            st.write("Use the new tables for Ads lead → proposal → booking → campaign.")
            st.divider()

            # Pick an advertiser lead (or create quickly)
            leads = conn.execute(text("""
                SELECT adv_lead_id, COALESCE(company_name,'') AS company_name, COALESCE(status,'') AS status
                FROM advertiser_leads
                ORDER BY created_at DESC
                LIMIT 200
            """)).mappings().all()
            lead_map = {f"{(r['company_name'] or r['adv_lead_id'])}  | {r['status']}": r["adv_lead_id"] for r in leads} if leads else {}
            adv_lead_id = st.selectbox("Select Advertiser Lead", list(lead_map.keys())) if lead_map else None
            if adv_lead_id:
                adv_lead_id = lead_map[adv_lead_id]

            if selected_stage != 4:
                st.info("For now, the workflow UI is fully implemented for **Stage 4 — Booking (Date Lock)**. Other stages can continue in existing pages until we expand them.")
                return

            st.markdown("## Stage 4 — Booking (Date Lock)")
            if not adv_lead_id:
                st.warning("Create/select an advertiser lead first (Stage 1).")
                return

            # Dates
            colA, colB = st.columns(2)
            with colA:
                start_d = st.date_input("Campaign Start Date", value=date.today())
            with colB:
                end_d = st.date_input("Campaign End Date", value=date.today())

            if end_d < start_d:
                st.error("End date must be on/after start date.")
                return

            # Screen picker (from screens table)
            screen_rows = conn.execute(text("""
                SELECT screen_id, COALESCE(screen_name,'') AS screen_name, COALESCE(city,'') AS city
                FROM screens
                ORDER BY created_at DESC
                LIMIT 500
            """)).mappings().all()

            if not screen_rows:
                st.warning("No screens found in `screens` table.")
                return

            screen_labels = [f"{r['screen_id']} | {r.get('screen_name','')} | {r.get('city','')}" for r in screen_rows]
            label_to_id = {lbl: r["screen_id"] for lbl, r in zip(screen_labels, screen_rows)}

            selected_labels = st.multiselect("Select Screens to Book", screen_labels)
            selected_screen_ids = [label_to_id[lbl] for lbl in selected_labels]

            if st.button("✅ Confirm Booking + Lock Screens", type="primary", disabled=not selected_screen_ids):
                conflicts = _ads_conflicts(conn, selected_screen_ids, start_d, end_d)
                if conflicts:
                    st.error("These screens are already booked in the selected date range:")
                    st.write(conflicts)
                else:
                    booking_id = f"BK_{uuid.uuid4().hex[:12].upper()}"
                    campaign_id = f"CP_{uuid.uuid4().hex[:12].upper()}"
                    # Create booking
                    conn.execute(text("""
                        INSERT INTO ad_bookings (booking_id, adv_lead_id, campaign_start, campaign_end, status, created_by)
                        VALUES (:bid, :lid, :sd, :ed, 'Confirmed', :by)
                    """), {"bid": booking_id, "lid": adv_lead_id, "sd": str(start_d), "ed": str(end_d), "by": getattr(rt, "USER", "system")})

                    # Create campaign (minimal)
                    conn.execute(text("""
                        INSERT INTO ad_campaigns (campaign_id, booking_id, client_name, go_live_date, status, created_by)
                        VALUES (:cid, :bid, :cn, :gd, 'Planned', :by)
                    """), {"cid": campaign_id, "bid": booking_id, "cn": "", "gd": str(start_d), "by": getattr(rt, "USER", "system")})

                    # Lock screens
                    _ads_block_screens(conn, campaign_id, selected_screen_ids, start_d, end_d)

                    st.success(f"Booking confirmed: {booking_id}. Screens locked from {start_d} to {end_d}.")
                    st.rerun()

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

        # Add new workflow page without disturbing existing pages
        workflow_label = "✅ Workflow (Stages)"
        if workflow_label not in menu:
            menu = [workflow_label] + list(menu)

        page_label = st.selectbox("Navigation", menu, key=f"nav_{rt.SECTION}")

        st.markdown("### 🔎 Global Search")
        with st.form("global_search_form", clear_on_submit=False):
            gq = st.text_input("Search across modules", key="global_search_term")
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

    # Convert menu label (with emoji) to PAGE_KEY (strip emoji prefix)
    # Legacy router expects PAGE_KEY like "Home", "Leads Pipeline", etc.
    
    # ---- New Workflow (Stages) page (does not affect existing routers) ----
    if page_label == "✅ Workflow (Stages)":
        _render_workflow(rt.SECTION)
        return
    
    rt.PAGE_KEY = rt.page_key_from_label(page_label) if hasattr(rt, "page_key_from_label") else rt.strip_menu_emoji(page_label)

    # ---- Route to module router ----
    if rt.SECTION == rt.SECTION_INSTALL:
        route_install(rt.PAGE_KEY)
    else:
        route_ads(rt.PAGE_KEY)


if __name__ == "__main__":
    main()
