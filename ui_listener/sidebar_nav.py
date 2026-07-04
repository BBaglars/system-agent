"""
Shared sidebar navigation for all NetSkill Agent pages.

Import and call render_sidebar_nav() immediately after st.set_page_config()
on every page so the navigation menu appears consistently at the top of the
sidebar, above any page-specific content.
"""

import streamlit as st


def render_sidebar_nav() -> None:
    """Render the custom top-level navigation inside st.sidebar."""
    with st.sidebar:
        st.markdown("### 🌐 NetSkill Agent")

        st.page_link("app.py",                      label="Sistem Özeti",    icon="🏠")
        st.page_link("pages/01_traffic_monitor.py", label="Trafik Monitörü", icon="📡")
        st.page_link("pages/02_copilot_chat.py",    label="Siber Copilot",   icon="🤖")

        st.divider()
