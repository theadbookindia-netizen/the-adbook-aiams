import streamlit as st
st.write("✅ AIAMS v9.0 is running")
st.stop()

import streamlit as st

st.set_page_config(page_title="AIAMS v9.0", layout="wide")

st.image("assets/logo.png", width=180)
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
