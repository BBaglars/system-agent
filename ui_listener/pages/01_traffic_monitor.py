"""
Live Traffic Monitor — Professional Cybersecurity Dashboard.

A Wireshark-inspired control panel built on top of the eBPF network sensor.
Features: KPI metrics, sidebar filtering, colour-coded connection state table,
and a packet-detail inspector panel.
"""

import json
import socket
import sys
import time
from pathlib import Path
from typing import Any

import pandas as pd
import streamlit as st

# ---------------------------------------------------------------------------
# Path bootstrap — makes imports work regardless of launch directory.
# ---------------------------------------------------------------------------
_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from api.orchestrator_client import get_memory_events
from config import MAX_DISPLAYED_EVENTS, TRAFFIC_REFRESH_INTERVAL_MS
from sidebar_nav import render_sidebar_nav


# ---------------------------------------------------------------------------
# On-demand reverse DNS lookup — cached per IP for 1 hour.
# Called only when the user clicks a row, never on every table refresh.
# ---------------------------------------------------------------------------
@st.cache_data(ttl=3600)
def resolve_hostname(ip: str) -> str:
    """Return the PTR hostname for *ip*, or 'Not Resolved' on failure.

    Uses socket.gethostbyaddr which performs a blocking reverse-DNS query.
    Results are memoised by Streamlit for TTL seconds so repeated clicks
    on the same IP return instantly without a network round-trip.
    """
    if not ip or ip in ("N/A", "0.0.0.0"):
        return "Not Resolved"
    try:
        hostname, *_ = socket.gethostbyaddr(ip)
        return hostname
    except (socket.herror, socket.gaierror, OSError):
        return "Not Resolved"

# ---------------------------------------------------------------------------
# Page config (must be the very first Streamlit call in this file).
# ---------------------------------------------------------------------------
st.set_page_config(
    page_title="NetSkill Agent — Trafik Monitörü",
    page_icon="🌐",
    layout="wide",
)

render_sidebar_nav()

# ---------------------------------------------------------------------------
# Custom CSS — dark-terminal aesthetic, coloured state badges.
# ---------------------------------------------------------------------------
st.markdown(
    """
    <style>
    /* ── Page chrome ─────────────────────────────────────────────────── */
    [data-testid="stAppViewContainer"] { background: #0d1117; color: #c9d1d9; }
    [data-testid="stSidebar"]          { border-right: 1px solid #30363d; }
    [data-testid="stHeader"]           { background: transparent; }

    /* ── Sidebar widget backgrounds — match the sidebar tone ─────────── */
    /* multiselect container */
    section[data-testid="stSidebar"] [data-testid="stMultiSelect"] > div:first-child,
    section[data-testid="stSidebar"] [data-baseweb="select"] > div,
    section[data-testid="stSidebar"] [data-baseweb="input"] > div {
        background-color: #2d3a4a !important;
        border-color: #3d4f63 !important;
        border-radius: 6px !important;
    }
    /* text input field */
    section[data-testid="stSidebar"] input[type="text"] {
        background-color: #2d3a4a !important;
        border-color: #3d4f63 !important;
        border-radius: 6px !important;
        color: #e2e8f0 !important;
    }
    /* selected tags inside multiselect */
    section[data-testid="stSidebar"] [data-baseweb="tag"] {
        background-color: #3b5a7a !important;
    }

    /* ── KPI cards ───────────────────────────────────────────────────── */
    div[data-testid="stMetric"] {
        background: #161b22;
        border: 1px solid #30363d;
        border-radius: 10px;
        padding: 16px 20px;
    }
    div[data-testid="stMetric"] label { color: #8b949e !important; font-size: 0.78rem; letter-spacing: .06em; text-transform: uppercase; }
    div[data-testid="stMetric"] [data-testid="stMetricValue"] { color: #e6edf3 !important; font-size: 2rem; font-weight: 700; }

    /* ── Section headers ─────────────────────────────────────────────── */
    .section-title {
        font-size: 0.7rem;
        font-weight: 600;
        letter-spacing: .1em;
        text-transform: uppercase;
        color: #8b949e;
        margin: 12px 0 6px 0;
    }

    /* ── Status pills ────────────────────────────────────────────────── */
    .pill-ok  { background:#1a3a2a; color:#3fb950; border:1px solid #238636;
                border-radius:20px; padding:2px 12px; font-size:.75rem; font-weight:600; display:inline-block; }
    .pill-err { background:#3a1a1a; color:#f85149; border:1px solid #da3633;
                border-radius:20px; padding:2px 12px; font-size:.75rem; font-weight:600; display:inline-block; }

    /* ── Detail inspector meta card ──────────────────────────────────── */
    .meta-card {
        background: #161b22;
        border: 1px solid #30363d;
        border-radius: 8px;
        padding: 18px 20px;
        line-height: 1.9;
    }
    .meta-label { color: #8b949e; font-size: 0.72rem; text-transform: uppercase;
                  letter-spacing: .06em; display: block; margin-top: 10px; }
    .meta-value { color: #e6edf3; font-family: "SFMono-Regular", Consolas, monospace;
                  font-size: 0.85rem; }

    /* ── Hide the glide-data-grid selection checkbox column ──────────── */
    /* The checkbox column is the first fixed column rendered by the grid.
       Streamlit renders the table on a <canvas>, so we cannot target
       individual cells directly.  Instead we zero-out the fixed-columns
       overlay wrapper that hosts the checkbox header + rows. */
    [data-testid="stDataFrameGlideDataEditor"] > div > div:nth-child(1) > div:nth-child(1) {
        display: none !important;
    }
    /* Shift the scrollable body back so it fills the freed space */
    [data-testid="stDataFrameGlideDataEditor"] > div > div:nth-child(2) {
        left: 0 !important;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

# ---------------------------------------------------------------------------
# Header
# ---------------------------------------------------------------------------
col_title, col_status = st.columns([4, 1])
with col_title:
    st.markdown("## 🌐 Trafik Monitörü")
    st.caption("Gerçek zamanlı eBPF çekirdek olayları · Her 2 saniyede otomatik yenilenir")

# ---------------------------------------------------------------------------
# Data fetch — index-stable snapshot strategy.
#
# Root problem: on_select="rerun" triggers a full page rerun the instant the
# user clicks.  That rerun calls get_memory_events() and new packets arrive
# at the top of the list, pushing every existing row down by K positions.
# df.iloc[selected_index] therefore points to a completely different packet.
#
# Solution: remember whether the PREVIOUS render had an active row selection
# (_prev_was_selected).  If it did, skip the live fetch entirely and reuse
# the exact same event list (_snapshot_events) so row indices stay stable.
# Only when the user deselects (clicks away) do we let the live fetch resume.
# ---------------------------------------------------------------------------
_prev_was_selected: bool = bool(st.session_state.get("_prev_selected_rows"))

if _prev_was_selected:
    # Stay on the frozen snapshot — indices must not move while user inspects.
    raw_events: list[dict[str, Any]] = st.session_state.get("_snapshot_events") or []
    if not raw_events:
        # Safety fallback: snapshot somehow lost, recover gracefully.
        raw_events = get_memory_events()
else:
    # Live mode: fetch fresh data and save it for potential future freeze.
    raw_events = get_memory_events()
    st.session_state["_snapshot_events"] = raw_events

if not raw_events:
    with col_status:
        st.markdown('<span class="pill-err">● OFFLINE</span>', unsafe_allow_html=True)
    st.warning(
        "⏳ Henüz olay alınmadı. "
        "eBPF sensörünün ve orkestratörün çalıştığından emin ol."
    )
    time.sleep(TRAFFIC_REFRESH_INTERVAL_MS / 1000)
    st.rerun()

with col_status:
    st.markdown('<span class="pill-ok">● LIVE</span>', unsafe_allow_html=True)

# ---------------------------------------------------------------------------
# Build base DataFrame (newest-first)
# ---------------------------------------------------------------------------
display_events = list(reversed(raw_events[-MAX_DISPLAYED_EVENTS:]))
df_raw = pd.DataFrame(display_events)

# Ensure expected columns exist with sensible defaults.
for col, default in {
    "pid": 0, "comm": "", "ip_address": "", "dport": 0,
    "tcp_state": None, "resolved_hostname": "",
}.items():
    if col not in df_raw.columns:
        df_raw[col] = default

# Numeric coercions.
df_raw["pid"]    = pd.to_numeric(df_raw["pid"],    errors="coerce").astype("Int64")
df_raw["dport"]  = pd.to_numeric(df_raw["dport"],  errors="coerce").astype("Int64")
df_raw["tcp_state"] = pd.to_numeric(df_raw["tcp_state"], errors="coerce")

# ---------------------------------------------------------------------------
# KPI Metrics (top of page)
# ---------------------------------------------------------------------------
total_events  = len(raw_events)
established   = int((df_raw["tcp_state"] == 1).sum())
refused       = int((df_raw["tcp_state"] == 7).sum())

top_app = "—"
if "comm" in df_raw.columns and not df_raw["comm"].empty:
    top_app_series = df_raw["comm"].replace("", pd.NA).dropna()
    if not top_app_series.empty:
        top_app = top_app_series.value_counts().idxmax()

k1, k2, k3, k4 = st.columns(4)
k1.metric("📦 Toplam Olay",          f"{total_events:,}")
k2.metric("✅ Bağlantı Kuruldu",     f"{established:,}")
k3.metric("❌ Kapatıldı / Reddedildi", f"{refused:,}")
k4.metric("🏆 En Aktif Süreç",       top_app)

st.divider()

# ---------------------------------------------------------------------------
# Sidebar — Filters
# ---------------------------------------------------------------------------
with st.sidebar:
    st.markdown("### 🔍 Görüntüleme Filtreleri")

    st.markdown('<p class="section-title">Uygulama</p>', unsafe_allow_html=True)
    all_apps = sorted(df_raw["comm"].replace("", pd.NA).dropna().unique().tolist())
    selected_apps: list[str] = st.multiselect(
        "Süreç (comm)",
        options=all_apps,
        default=[],
        placeholder="Tüm süreçler",
        label_visibility="collapsed",
    )

    st.markdown('<p class="section-title">Hedef Port</p>', unsafe_allow_html=True)
    all_ports = sorted(
        df_raw["dport"].dropna().astype(int).unique().tolist()
    )
    selected_ports: list[int] = st.multiselect(
        "Hedef Port",
        options=all_ports,
        default=[],
        format_func=lambda p: f":{p}",
        placeholder="Tüm portlar",
        label_visibility="collapsed",
    )

    st.markdown('<p class="section-title">Bağlantı Durumu</p>', unsafe_allow_html=True)
    show_established = st.checkbox("✅ Kuruldu  (durum = 1)", value=True)
    show_refused     = st.checkbox("❌ Kapatıldı/Reddedildi (durum = 7)", value=True)
    show_unknown     = st.checkbox("❓ Bilinmeyen durum",                  value=True)

    st.markdown('<p class="section-title">Arama</p>', unsafe_allow_html=True)
    search_term: str = st.text_input(
        "IP adresi",
        placeholder="örn.  142.250  veya  8.8",
        label_visibility="collapsed",
    )

    st.divider()
    st.caption(
        f"Önbellek: **{total_events}** olay · "
        f"Gösterilen: **{min(total_events, MAX_DISPLAYED_EVENTS)}**"
    )

# ---------------------------------------------------------------------------
# Apply filters
# ---------------------------------------------------------------------------
df = df_raw.copy()

if selected_apps:
    df = df[df["comm"].isin(selected_apps)]

if selected_ports:
    df = df[df["dport"].isin(selected_ports)]

# State filter — build an OR mask from active checkboxes.
state_mask = pd.Series(False, index=df.index)
if show_established:
    state_mask |= (df["tcp_state"] == 1)
if show_refused:
    state_mask |= (df["tcp_state"] == 7)
if show_unknown:
    state_mask |= (~df["tcp_state"].isin([1, 7]))
df = df[state_mask]

if search_term.strip():
    term = search_term.strip().lower()
    ip_match = df["ip_address"].fillna("").str.lower().str.contains(term, regex=False)
    df = df[ip_match]

# ---------------------------------------------------------------------------
# Presentation DataFrame — friendly column names + state badge column
# ---------------------------------------------------------------------------
STATE_LABEL = {1: "✅ KURULDU", 7: "❌ KAPATILDI/REDDEDİLDİ"}

df_display = df[["pid", "comm", "ip_address", "dport", "tcp_state"]].copy()
df_display["State"] = df_display["tcp_state"].map(STATE_LABEL).fillna("❓ BİLİNMİYOR")

df_display.rename(
    columns={
        "pid":       "PID",
        "comm":      "Süreç",
        "ip_address":"Hedef IP",
        "dport":     "Hedef Port",
        "tcp_state": "_state_num",
    },
    inplace=True,
)

visible_cols = ["PID", "Süreç", "Hedef IP", "Hedef Port", "State"]
df_display = df_display[visible_cols]

# ---------------------------------------------------------------------------
# Pandas Styler — surgical colour coding.
#
# Design principle: normal traffic (ESTABLISHED) should NOT shout.
# Only anomalies (CLOSED/REFUSED) get a full-row highlight so analysts
# can spot problems at a glance without cognitive overload.
# ---------------------------------------------------------------------------

def _highlight_anomaly_rows(row: pd.Series) -> list[str]:
    """Apply a subtle dark-red wash only to refused/closed connections."""
    if row["State"] == "❌ KAPATILDI/REDDEDİLDİ":
        return ["background-color: rgba(248, 81, 73, 0.09);"] * len(row)
    return [""] * len(row)

def _style_state_cell(val: str) -> str:
    """Colour the State cell text; leave the row background untouched."""
    if val == "✅ KURULDU":
        return "color: #3fb950; font-weight: 500;"
    if val == "❌ KAPATILDI/REDDEDİLDİ":
        return "color: #f85149; font-weight: 600;"
    return "color: #8b949e;"

styled = (
    df_display.style
    .apply(_highlight_anomaly_rows, axis=1)
    .map(_style_state_cell, subset=["State"])
)

# ---------------------------------------------------------------------------
# Packet table with row-selection for the detail inspector
# ---------------------------------------------------------------------------
st.markdown(
    f"<p style='color:#8b949e; font-size:.8rem; margin-bottom:4px;'>"
    f"<b style='color:#e6edf3'>{len(df_display)}</b> paket gösteriliyor "
    f"{'(filtrelenmiş) ' if len(df_display) != len(df_raw) else ''}"
    f"· detay için bir satıra tıkla</p>",
    unsafe_allow_html=True,
)

selection = st.dataframe(
    styled,
    use_container_width=True,
    height=440,
    hide_index=True,
    on_select="rerun",
    selection_mode="single-row",
    key="packet_table",
)

# ---------------------------------------------------------------------------
# Selection state — persisted by content, not by row index.
#
# Problem: st.dataframe reports selected rows by positional index.
# When the table auto-refreshes new events arrive and every existing row
# shifts one position down, so index N now points to a completely different
# packet.  The fix is to:
#   1. On a fresh selection, snapshot the actual row dict into session_state.
#   2. On every subsequent rerun check whether the dataframe still reports a
#      selection; if not (user clicked away), clear the snapshot.
#   3. Pause the auto-refresh timer while a packet is being inspected so the
#      detail panel stays stable — exactly like Wireshark's behaviour when
#      you click a packet.
# ---------------------------------------------------------------------------
selected_rows: list[int] = (
    selection.selection.rows if hasattr(selection, "selection") else []
)

# Persist selection presence so the NEXT render knows whether to freeze the fetch.
st.session_state["_prev_selected_rows"] = selected_rows

if selected_rows:
    # df was built from the frozen/fresh snapshot decided at the top of this
    # render, so df.iloc[idx] is always the packet the user actually clicked.
    idx = selected_rows[0]
    st.session_state["selected_packet"] = df.iloc[idx].to_dict()
elif "selected_packet" in st.session_state:
    # User deselected — unfreeze everything.
    del st.session_state["selected_packet"]
    st.session_state.pop("_prev_selected_rows", None)

# ---------------------------------------------------------------------------
# Packet Detail Inspector
# ---------------------------------------------------------------------------
frozen_packet: dict | None = st.session_state.get("selected_packet")

detail_header_col, freeze_badge_col = st.columns([3, 1])
with detail_header_col:
    st.markdown("#### 🔬 Paket Detayları")
with freeze_badge_col:
    if frozen_packet:
        st.markdown(
            '<span style="background:#1a2a3a;color:#58a6ff;border:1px solid #1f6feb;'
            'border-radius:20px;padding:3px 12px;font-size:.73rem;font-weight:600;">'
            "🔒 DONDURULDU — devam için başka yere tıkla</span>",
            unsafe_allow_html=True,
        )

if frozen_packet:
    raw_row = frozen_packet

    # Normalise pandas Int64 / NA so json.dumps serialises cleanly.
    serialisable: dict[str, Any] = {}
    for k, v in raw_row.items():
        try:
            serialisable[k] = int(v) if pd.notna(v) and isinstance(v, (int, float)) else (
                None if pd.isna(v) else v  # type: ignore[arg-type]
            )
        except (TypeError, ValueError):
            serialisable[k] = str(v) if v is not None else None

    state_val = raw_row.get("tcp_state")
    state_badge = (
        '<span class="pill-ok">● ESTABLISHED</span>'    if state_val == 1 else
        '<span class="pill-err">● CLOSED / REFUSED</span>' if state_val == 7 else
        '<span style="color:#8b949e;">● UNKNOWN</span>'
    )

    proc = str(raw_row.get("comm", "N/A") or "N/A")
    ip   = str(raw_row.get("ip_address", "N/A") or "N/A")
    port = raw_row.get("dport", "N/A")
    pid  = raw_row.get("pid", "N/A")

    # On-demand PTR lookup — result is served from Streamlit's cache after
    # the first query so subsequent clicks on the same IP are instant.
    with st.spinner("Alan adı çözümleniyor…"):
        resolved = resolve_hostname(ip)

    # Use the PTR record as the display target when available.
    display_target = resolved if resolved != "Not Resolved" else ip

    # [1, 2] — narrow meta panel on the left, wide JSON viewer on the right.
    left_col, right_col = st.columns([1, 2])

    with left_col:
        st.markdown(
            f"""
            <div class="meta-card">
              <span class="meta-label">Bağlantı Sonucu</span>
              {state_badge}

              <span class="meta-label">Süreç</span>
              <span class="meta-value">{proc}</span>

              <span class="meta-label">Hedef</span>
              <span class="meta-value">{display_target}:{port}</span>

              <span class="meta-label">Ham Hedef IP</span>
              <span class="meta-value">{ip}</span>

              <span class="meta-label">Çözümlenen Alan Adı</span>
              <span class="meta-value">{resolved}</span>

              <span class="meta-label">PID</span>
              <span class="meta-value">{pid}</span>
            </div>
            """,
            unsafe_allow_html=True,
        )

        st.markdown("&nbsp;", unsafe_allow_html=True)

        # Routes to the AI copilot page with this packet pre-filled as context.
        if st.button("🤖 Bu Paketi Yapay Zekaya Sor", use_container_width=True):
            question = (
                f"Bu paketi analiz et: Process={proc}, "
                f"Dest={display_target}:{port} (IP: {ip}), "
                f"State={'ESTABLISHED' if state_val == 1 else 'REFUSED'}"
            )
            st.session_state["copilot_prefill"] = question
            st.switch_page("pages/02_copilot_chat.py")

    with right_col:
        # st.code gives syntax highlighting, a copy button, and correct sizing
        # for free — no custom HTML required.
        st.code(
            json.dumps(serialisable, indent=2, ensure_ascii=False),
            language="json",
        )

else:
    st.markdown(
        '<div style="color:#8b949e; padding:20px 0; font-size:.85rem;">'
        "↑ Detayları görmek için yukarıdaki tablodan bir satıra tıkla."
        "</div>",
        unsafe_allow_html=True,
    )

# ---------------------------------------------------------------------------
# Auto-refresh — paused while the analyst is inspecting a packet.
#
# Resuming is as simple as clicking anywhere outside the selected row to
# deselect it, which clears session_state["selected_packet"] (see above)
# and lets the timer run again on the next rerun.
# ---------------------------------------------------------------------------
if not frozen_packet:
    time.sleep(TRAFFIC_REFRESH_INTERVAL_MS / 1000)
    st.rerun()
