"""
Security Copilot — conversational interface to the Llama 3.1 network agent.

Each user question triggers POST /api/chat on the orchestrator.  The full
conversation history is persisted in a local SQLite database (chat_history.db)
so it survives page refreshes and browser restarts.

Session lifecycle
-----------------
1. On first load: restore the most recent session from SQLite (if any),
   otherwise create a fresh one with a new UUID.
2. On F5 (refresh): st.session_state is lost, but the session_id is
   re-derived from SQLite and all messages are reloaded from disk.
3. On "Clear Cache": all rows are deleted from SQLite and the in-memory
   state is reset to a clean slate.
"""

import sys
import uuid
from pathlib import Path
from typing import TypedDict

import streamlit as st

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from api.orchestrator_client import get_memory_events, post_chat
from chat_history import (
    ChatMessage,
    clear_all_history,
    create_conversation,
    get_most_recent_session,
    load_messages,
    save_message,
)

# ── Page header ────────────────────────────────────────────────────────────────
st.title("🤖 Security Copilot")
st.caption(
    "Ask the Llama 3.1 agent anything about current network activity. "
    "Conversation history is persisted across page refreshes."
)

# ── Session initialisation ─────────────────────────────────────────────────────
# We use two keys in st.session_state:
#   "conversation_id"  — integer PK in the SQLite messages table
#   "messages"         — in-memory mirror of the same rows (avoids re-reading DB
#                        on every Streamlit rerun caused by widgets)

def _bootstrap_session() -> None:
    """Ensure session_state holds a valid conversation_id and messages list.

    Called on every Streamlit run.  If session_state already has a
    conversation_id we do nothing — the in-memory mirror is already up to date.
    If session_state was wiped (F5), we restore from SQLite.
    """
    if "conversation_id" in st.session_state:
        return  # already initialised this browser session

    # Attempt to restore the most recent existing conversation.
    latest = get_most_recent_session()
    if latest:
        session_id, conv_id = latest
        st.session_state["session_id"]     = session_id
        st.session_state["conversation_id"] = conv_id
        st.session_state["messages"]       = load_messages(conv_id)
    else:
        # No history at all — start a brand-new conversation.
        session_id = str(uuid.uuid4())
        conv_id    = create_conversation(session_id)
        st.session_state["session_id"]     = session_id
        st.session_state["conversation_id"] = conv_id
        st.session_state["messages"]       = []


_bootstrap_session()

messages: list[ChatMessage]  = st.session_state["messages"]
conversation_id: int         = st.session_state["conversation_id"]

# Pre-filled question forwarded from the Traffic Monitor detail panel.
_prefill: str | None = st.session_state.pop("copilot_prefill", None)

# ── Sidebar ────────────────────────────────────────────────────────────────────
with st.sidebar:
    st.subheader("📊 Buffer Stats")
    try:
        event_count = len(get_memory_events())
        st.metric("Events in memory", event_count)
    except Exception:  # noqa: BLE001
        st.warning("Could not reach orchestrator.")

    st.divider()

    if st.button("🗑️ Clear Cache / Geçmişi Temizle", use_container_width=True):
        # 1. Wipe every row from SQLite.
        clear_all_history()
        # 2. Create a fresh conversation immediately so the app is usable at once.
        new_session_id = str(uuid.uuid4())
        new_conv_id    = create_conversation(new_session_id)
        # 3. Reset session_state in one pass to avoid stale keys.
        st.session_state["session_id"]      = new_session_id
        st.session_state["conversation_id"] = new_conv_id
        st.session_state["messages"]        = []
        st.rerun()

# ── Render existing conversation ───────────────────────────────────────────────
for message in messages:
    with st.chat_message(message["role"]):
        st.markdown(message["content"])

# ── Chat input ─────────────────────────────────────────────────────────────────
prompt: str | None = st.chat_input(
    "Ağ trafiği hakkında veya şüpheli bir durum olup olmadığına dair bir soru sor…"
)

# Honour a pre-filled question forwarded from the Traffic Monitor detail panel.
if _prefill and not prompt:
    prompt = _prefill

if prompt:
    # ── 1. Persist and display the user's question immediately ─────────────────
    save_message(conversation_id, "user", prompt)
    messages.append(ChatMessage(role="user", content=prompt))

    with st.chat_message("user"):
        st.markdown(prompt)

    # ── 2. Build the history slice sent to the orchestrator ────────────────────
    # We send the last 6 messages (= 3 full turns) as context.  The list
    # already contains the current user message we just appended.
    history_slice = messages[-6:]

    # ── 3. Call the orchestrator ───────────────────────────────────────────────
    with st.chat_message("assistant"):
        with st.spinner("Ajan ağ snapshot'ını analiz ediyor… (Bu işlem 30–90 saniye sürebilir)"):
            try:
                report: str = post_chat(prompt, list(history_slice))
            except Exception as exc:  # noqa: BLE001
                report = f"❌ **Unexpected client error:** {exc}"

        st.markdown(report)

    # ── 4. Persist and cache the assistant's reply ─────────────────────────────
    save_message(conversation_id, "assistant", report)
    messages.append(ChatMessage(role="assistant", content=report))
