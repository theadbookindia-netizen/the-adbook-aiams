import streamlit as st

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
    rt.PAGE_KEY = rt.page_key_from_label(page_label) if hasattr(rt, "page_key_from_label") else rt.strip_menu_emoji(page_label)

    # ---- Route to module router ----
    if rt.SECTION == rt.SECTION_INSTALL:
        route_install(rt.PAGE_KEY)
    else:
        route_ads(rt.PAGE_KEY)

if __name__ == "__main__":
    main()
