"""
Open Claw — Network Security Agent
Main entry point for the Streamlit UI.

Run with:
    cd ui_listener
    source venv/bin/activate
    pip install -r requirements.txt
    streamlit run app.py
"""

import streamlit as st

st.set_page_config(
    page_title="Open Claw — Network Security Agent",
    page_icon="🦞",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.title("🦞 Open Claw — Network Security Agent")

st.info(
    "Use the **left sidebar** to navigate between panels:\n\n"
    "- 📡 **Traffic Monitor** — Live eBPF network event table (auto-refreshes every 2 s)\n"
    "- 🤖 **Copilot Chat** — Ask the AI agent questions about current network activity",
    icon="👈",
)

st.divider()

col_left, col_right = st.columns(2)

with col_left:
    st.subheader("📡 Traffic Monitor")
    st.caption(
        "Streams real-time TCP connection events captured by the eBPF kernel sensor. "
        "Each row represents a single outbound connection attempt."
    )

with col_right:
    st.subheader("🤖 Copilot Chat")
    st.caption(
        "Ask natural-language questions about network activity. "
        "The Llama 3.1 agent analyses a live snapshot and returns a Markdown security report."
    )

st.divider()
st.caption("Powered by eBPF · Go · Node.js · LangChain · Llama 3.1 · Streamlit")
