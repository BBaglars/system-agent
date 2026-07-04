"""
Security Copilot — conversational interface to the Llama 3.1 network agent.

Features
--------
- Persistent SQLite chat history (survives F5 / browser restarts)
- Session archive sidebar with clickable past conversations
- Quick-action chips for one-click agent prompts
- Dynamic spinner text based on heuristic tool detection
"""

import sys
import uuid
from pathlib import Path

import streamlit as st

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from api.orchestrator_client import get_memory_events, post_chat
from chat_history import (
    ChatMessage,
    ConversationSummary,
    clear_all_history,
    create_conversation,
    get_most_recent_session,
    list_all_conversations,
    load_messages,
    save_message,
)

# ── Page config ────────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="Open Claw — Security Copilot",
    page_icon="🤖",
    layout="wide",
)

# ── Dark-theme CSS tweaks ──────────────────────────────────────────────────────
st.markdown(
    """
    <style>
    /* Chip buttons — compact, borderless feel */
    div[data-testid="stHorizontalBlock"] button[kind="secondary"] {
        font-size: 0.78rem;
        padding: 4px 8px;
        border-radius: 20px;
    }
    /* Active sidebar session button — subtle left accent */
    section[data-testid="stSidebar"] button[kind="primary"] {
        border-left: 3px solid #58a6ff;
        border-radius: 4px;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

# ── Quick-action chip definitions ─────────────────────────────────────────────
# Each entry: (display label, full prompt sent to the agent)
CHIPS: list[tuple[str, str]] = [
    ("📦 eBPF Snapshot",       "Son ağ bağlantılarını analiz et"),
    ("🔌 Port Envanteri",       "Hangi portlar şu an dinleniyor?"),
    ("🩺 localhost:3000 Test",  "3000 portuna bağlantıyı test et"),
    ("🌐 DNS Sağlığı",          "google.com için DNS çözümlemesini kontrol et"),
    ("🔍 HTTPS Trafiği",        "Son HTTPS (443) bağlantılarını göster"),
]

# ── Tool-name heuristic for dynamic spinner messages ──────────────────────────
_TOOL_SPINNER: dict[str | None, str] = {
    "list_listening_ports": "🔌 Ajan sistem port tablosunu tarıyor…",
    "probe_local_port":     "🩺 Ajan TCP bağlantısı test ediyor…",
    "resolve_dns_health":   "🌐 Ajan DNS çözümleme zincirini sorguluyor…",
    "fetch_snapshot_data":  "📦 Ajan eBPF snapshot'ını analiz ediyor…",
    "analyze_external_ip":  "🔍 Ajan IP adresini araştırıyor…",
    None:                   "🤔 Ajan soruyu değerlendiriyor…",
}


def _guess_tool(prompt: str) -> str | None:
    """Heuristically predict which agent tool will be triggered.

    This is purely cosmetic — it drives the spinner message only and has zero
    influence on the actual tool the orchestrator selects.
    """
    lower = prompt.lower()
    if any(w in lower for w in ["port envanteri", "hangi port", "dinleniyor", "listening", "açık port"]):
        return "list_listening_ports"
    if any(w in lower for w in ["bağlanamıyorum", "bağlantıyı test", "probe", "test et", "yanıt vermiyor", "erişemiyorum"]):
        return "probe_local_port"
    if any(w in lower for w in ["dns", "domain", "açılmıyor", "çözümle", "siteye giremiyorum", "nslookup"]):
        return "resolve_dns_health"
    if any(w in lower for w in ["ip adres", "şüpheli ip", "analyze_external", "kim bu ip"]):
        return "analyze_external_ip"
    if any(w in lower for w in ["snapshot", "trafik", "bağlantı", "paket", "ağ", "https", "port 443"]):
        return "fetch_snapshot_data"
    return None


# ── Session bootstrap ─────────────────────────────────────────────────────────

def _bootstrap_session() -> None:
    """Ensure session_state has a valid conversation_id and messages list.

    On F5 / first load: session_state is empty → restore from SQLite.
    On normal rerun: session_state already holds the values → no-op.
    """
    if "conversation_id" in st.session_state:
        return

    latest = get_most_recent_session()
    if latest:
        session_id, conv_id = latest
        st.session_state["session_id"]      = session_id
        st.session_state["conversation_id"] = conv_id
        st.session_state["messages"]        = load_messages(conv_id)
    else:
        _start_new_session()


def _start_new_session() -> None:
    """Create a brand-new SQLite conversation and wire it into session_state."""
    session_id = str(uuid.uuid4())
    conv_id    = create_conversation(session_id)
    st.session_state["session_id"]      = session_id
    st.session_state["conversation_id"] = conv_id
    st.session_state["messages"]        = []


_bootstrap_session()

messages: list[ChatMessage] = st.session_state["messages"]
conversation_id: int        = st.session_state["conversation_id"]

# Pre-filled prompt forwarded from the Traffic Monitor "Ask AI" button.
_prefill: str | None = st.session_state.pop("copilot_prefill", None)
# Pre-filled prompt from a quick-action chip click (consumed once per rerun).
_chip_prefill: str | None = st.session_state.pop("chip_prefill", None)

# ── Sidebar ────────────────────────────────────────────────────────────────────
with st.sidebar:

    # ── Live buffer metric ─────────────────────────────────────────────────────
    st.markdown("### 📡 Open Claw")
    try:
        event_count = len(get_memory_events())
        st.metric("eBPF Events in buffer", f"{event_count:,}")
    except Exception:  # noqa: BLE001
        st.warning("⚠️ Orchestrator'a ulaşılamıyor.")

    st.divider()

    # ── Session archive ────────────────────────────────────────────────────────
    st.markdown("#### 📋 Oturum Arşivi")

    try:
        all_convs: list[ConversationSummary] = list_all_conversations()
    except Exception:  # noqa: BLE001
        all_convs = []

    if not all_convs:
        st.caption("Henüz geçmiş sohbet yok.")
    else:
        for conv in all_convs:
            # Format the timestamp to a compact local label.
            try:
                # created_at is stored as ISO-8601 (e.g. "2026-07-05T00:32:11")
                dt_part = conv["created_at"].split("T")
                date_label = dt_part[0][5:]             # "07-05"
                time_label = dt_part[1][:5] if len(dt_part) > 1 else ""  # "00:32"
                ts_label   = f"{date_label} {time_label}"
            except Exception:  # noqa: BLE001
                ts_label = "—"

            preview   = conv["preview"].strip()
            btn_label = f"{ts_label} · {preview}{'…' if len(preview) == 30 else ''}"
            is_active = (conv["id"] == conversation_id)

            if st.button(
                btn_label,
                key=f"conv_{conv['id']}",
                use_container_width=True,
                type="primary" if is_active else "secondary",
            ):
                if not is_active:
                    st.session_state["conversation_id"] = conv["id"]
                    st.session_state["session_id"]      = conv["session_id"]
                    st.session_state["messages"]        = load_messages(conv["id"])
                    st.rerun()

    st.divider()

    # ── Session actions ────────────────────────────────────────────────────────
    if st.button("➕ Yeni Sohbet", use_container_width=True):
        _start_new_session()
        st.rerun()

    if st.button("🗑️ Tümünü Temizle", use_container_width=True, type="secondary"):
        clear_all_history()
        _start_new_session()
        st.rerun()

# ── Page header ────────────────────────────────────────────────────────────────
st.markdown("## 🤖 Security Copilot")
st.caption(
    "Llama 3.1 ağ tanılama ajanına ağ trafiği, servis durumu veya bağlantı sorunları "
    "hakkında soru sor. Sohbet geçmişi kalıcı olarak kaydedilir."
)

# ── Render conversation history ────────────────────────────────────────────────
for message in messages:
    with st.chat_message(message["role"]):
        st.markdown(message["content"])

# ── Quick-action chips ─────────────────────────────────────────────────────────
chip_cols = st.columns(len(CHIPS))
for col, (label, preset) in zip(chip_cols, CHIPS):
    if col.button(label, use_container_width=True, key=f"chip_{label}"):
        st.session_state["chip_prefill"] = preset
        st.rerun()

# ── Chat input ─────────────────────────────────────────────────────────────────
prompt: str | None = st.chat_input(
    "Ağ trafiği hakkında veya bir bağlantı sorunu için soru sor…"
)

# Resolve prompt priority: typed > chip > traffic-monitor prefill
if not prompt and _chip_prefill:
    prompt = _chip_prefill
elif not prompt and _prefill:
    prompt = _prefill

# ── Handle prompt ──────────────────────────────────────────────────────────────
if prompt:
    # 1. Persist & show the user message immediately.
    save_message(conversation_id, "user", prompt)
    messages.append(ChatMessage(role="user", content=prompt))
    with st.chat_message("user"):
        st.markdown(prompt)

    # 2. Build the history slice (last 6 msgs = 3 full turns).
    history_slice = list(messages[-6:])

    # 3. Determine a meaningful spinner label from the prompt.
    guessed_tool   = _guess_tool(prompt)
    spinner_label  = _TOOL_SPINNER.get(guessed_tool, _TOOL_SPINNER[None])

    # 4. Call the orchestrator with dynamic feedback.
    with st.chat_message("assistant"):
        with st.spinner(spinner_label):
            try:
                report: str = post_chat(prompt, history_slice)
            except Exception as exc:  # noqa: BLE001
                report = f"❌ **İstemci hatası:** {exc}"

        st.markdown(report)

    # 5. Persist the assistant reply.
    save_message(conversation_id, "assistant", report)
    messages.append(ChatMessage(role="assistant", content=report))
