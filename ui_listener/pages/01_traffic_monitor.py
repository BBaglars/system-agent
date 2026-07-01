"""
Live Traffic Monitor — real-time eBPF network event table.

Polls GET /memory every 2 seconds and renders the events as a
sortable, auto-refreshing DataFrame.  Most-recent events appear
at the top so operators see the latest activity immediately.
"""

import sys
import time
from pathlib import Path

import pandas as pd
import streamlit as st

# Ensure the ui_listener root is on sys.path so relative imports work
# regardless of the working directory Streamlit is launched from.
_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from api.orchestrator_client import get_memory_events
from config import MAX_DISPLAYED_EVENTS, TRAFFIC_REFRESH_INTERVAL_MS

st.title("📡 Live Traffic Monitor")

# ── Status bar ────────────────────────────────────────────────────────────────
status_placeholder = st.empty()

# ── Fetch ─────────────────────────────────────────────────────────────────────
raw_events: list[dict] = get_memory_events()

if not raw_events:
    status_placeholder.warning(
        "⏳ No events yet. "
        "Waiting for the eBPF sensor to send data via the orchestrator…"
    )
    time.sleep(TRAFFIC_REFRESH_INTERVAL_MS / 1000)
    st.rerun()

# ── Build DataFrame ────────────────────────────────────────────────────────────
# Keep only the most recent MAX_DISPLAYED_EVENTS rows (tail of the circular buffer).
display_events = raw_events[-MAX_DISPLAYED_EVENTS:]

# Reverse so the newest event is at the top of the table.
display_events = list(reversed(display_events))

df = pd.DataFrame(display_events)

# Rename raw field names to human-readable column headers.
column_map: dict[str, str] = {
    "pid":        "PID",
    "comm":       "Process (Comm)",
    "ip_address": "Destination IP",
    "dport":      "Port",
    "daddr":      "Raw daddr",
}
df.rename(columns={k: v for k, v in column_map.items() if k in df.columns}, inplace=True)

# Show user-friendly columns first; hide the raw integer daddr if ip_address is present.
preferred_columns = ["PID", "Process (Comm)", "Destination IP", "Port"]
visible_columns = [c for c in preferred_columns if c in df.columns]
# Append any extra columns the sensor may add in the future.
extra_columns = [c for c in df.columns if c not in preferred_columns and c != "Raw daddr"]
df = df[visible_columns + extra_columns]

# Cast types for clean rendering.
if "PID" in df.columns:
    df["PID"] = pd.to_numeric(df["PID"], errors="coerce").astype("Int64")
if "Port" in df.columns:
    df["Port"] = pd.to_numeric(df["Port"], errors="coerce").astype("Int64")

# ── Render ─────────────────────────────────────────────────────────────────────
status_placeholder.success(
    f"✅ Showing **{len(df)}** most-recent events "
    f"(buffer contains {len(raw_events)} total). "
    f"Auto-refreshing every {TRAFFIC_REFRESH_INTERVAL_MS // 1000} s."
)

st.dataframe(
    df,
    use_container_width=True,
    height=600,
    hide_index=True,
)

# ── Auto-refresh loop ──────────────────────────────────────────────────────────
# Sleep for the configured interval, then trigger a full Streamlit re-run.
# This produces the "Wireshark-style" live-scrolling table effect.
time.sleep(TRAFFIC_REFRESH_INTERVAL_MS / 1000)
st.rerun()
