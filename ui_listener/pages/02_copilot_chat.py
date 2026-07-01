"""
Security Copilot — conversational interface to the Llama 3.1 network agent.

Each user question triggers POST /api/chat on the orchestrator.
The orchestrator freezes a network snapshot and runs a full LangChain
ReAct loop, returning a Markdown security report.

Conversation history is preserved in st.session_state for the duration
of the browser session.
"""

import sys
from pathlib import Path
from typing import TypedDict

import streamlit as st

# Ensure the ui_listener root is on sys.path regardless of launch directory.
_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from api.orchestrator_client import get_memory_events, post_chat

# ── Page config ────────────────────────────────────────────────────────────────
st.title("🤖 Security Copilot")
st.caption(
    "Ask the Llama 3.1 agent anything about current network activity. "
    "The agent will take a live snapshot and analyse it with its built-in tools."
)


# ── Session state helpers ──────────────────────────────────────────────────────
class ChatMessage(TypedDict):
    role: str      # "user" | "assistant"
    content: str


def _init_session() -> None:
    if "messages" not in st.session_state:
        st.session_state["messages"]: list[ChatMessage] = []


_init_session()

messages: list[ChatMessage] = st.session_state["messages"]

# ── Sidebar: quick stats ───────────────────────────────────────────────────────
with st.sidebar:
    st.subheader("📊 Buffer Stats")
    try:
        event_count = len(get_memory_events())
        st.metric("Events in memory", event_count)
    except Exception:  # noqa: BLE001
        st.warning("Could not reach orchestrator.")

    st.divider()
    if st.button("🗑️ Clear chat history"):
        st.session_state["messages"] = []
        st.rerun()

# ── Render existing conversation ───────────────────────────────────────────────
for message in messages:
    with st.chat_message(message["role"]):
        st.markdown(message["content"])

# ── Chat input ─────────────────────────────────────────────────────────────────
prompt: str | None = st.chat_input(
    "Ağ trafiği hakkında veya şüpheli bir durum olup olmadığına dair bir soru sor…"
)

if prompt:
    # 1. Display and persist the user's message immediately.
    with st.chat_message("user"):
        st.markdown(prompt)
    messages.append({"role": "user", "content": prompt})

    # 2. Call the orchestrator and stream back the report.
    with st.chat_message("assistant"):
        with st.spinner("Ajan ağ snapshot'ını analiz ediyor… (Bu işlem 30–90 saniye sürebilir)"):
            try:
                report: str = post_chat(prompt)
            except Exception as exc:  # noqa: BLE001
                # Surface unexpected errors without crashing the page.
                report = f"❌ **Unexpected client error:** {exc}"

        # Render the Markdown report returned by the LangChain agent.
        st.markdown(report)

    # 3. Persist the assistant's reply so it survives the next rerun.
    messages.append({"role": "assistant", "content": report})
