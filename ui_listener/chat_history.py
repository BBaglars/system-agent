"""
SQLite-backed chat history manager for the Open Claw UI layer.

All conversation data is persisted in a local file (chat_history.db) that
lives next to this module.  No external services or packages are required —
only the Python standard library's sqlite3 module is used.

Schema
------
conversations  — one row per chat session (UUID + timestamp)
messages       — ordered message log for each conversation
"""

import sqlite3
from datetime import datetime
from pathlib import Path
from typing import TypedDict

# The database file sits alongside this module so it is always found regardless
# of the working directory Streamlit is launched from.
_DB_PATH = Path(__file__).resolve().parent / "chat_history.db"

_DDL = """
CREATE TABLE IF NOT EXISTS conversations (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT    NOT NULL UNIQUE,
    created_at TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS messages (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    conversation_id INTEGER NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    role            TEXT    NOT NULL CHECK(role IN ('user', 'assistant')),
    content         TEXT    NOT NULL,
    created_at      TEXT    NOT NULL
);

-- Fast lookup of all messages belonging to a conversation.
CREATE INDEX IF NOT EXISTS idx_messages_conversation_id
    ON messages (conversation_id);
"""


# ── Types ─────────────────────────────────────────────────────────────────────

class ChatMessage(TypedDict):
    role: str       # "user" | "assistant"
    content: str


# ── Connection helper ─────────────────────────────────────────────────────────

def _connect() -> sqlite3.Connection:
    """Open (and if necessary initialise) the SQLite database."""
    conn = sqlite3.connect(_DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    # Enable foreign-key enforcement so CASCADE deletes work.
    conn.execute("PRAGMA foreign_keys = ON")
    conn.executescript(_DDL)
    conn.commit()
    return conn


# ── Public API ────────────────────────────────────────────────────────────────

def create_conversation(session_id: str) -> int:
    """Insert a new conversation row and return its integer primary key.

    If a conversation with the same session_id already exists (e.g. Streamlit
    hot-reloaded), the existing row is returned without duplication.
    """
    with _connect() as conn:
        conn.execute(
            "INSERT OR IGNORE INTO conversations (session_id, created_at) VALUES (?, ?)",
            (session_id, datetime.utcnow().isoformat()),
        )
        conn.commit()
        row = conn.execute(
            "SELECT id FROM conversations WHERE session_id = ?", (session_id,)
        ).fetchone()
        return int(row["id"])


def save_message(conversation_id: int, role: str, content: str) -> None:
    """Append a single message to the given conversation."""
    with _connect() as conn:
        conn.execute(
            "INSERT INTO messages (conversation_id, role, content, created_at) VALUES (?, ?, ?, ?)",
            (conversation_id, role, content, datetime.utcnow().isoformat()),
        )
        conn.commit()


def load_messages(conversation_id: int) -> list[ChatMessage]:
    """Return all messages for a conversation in chronological order."""
    with _connect() as conn:
        rows = conn.execute(
            "SELECT role, content FROM messages "
            "WHERE conversation_id = ? ORDER BY id ASC",
            (conversation_id,),
        ).fetchall()
    return [ChatMessage(role=row["role"], content=row["content"]) for row in rows]


def get_latest_conversation_id(session_id: str) -> int | None:
    """Return the integer PK for *session_id*, or None if it does not exist.

    Used on page load / F5 to restore the most recent chat session.
    """
    with _connect() as conn:
        row = conn.execute(
            "SELECT id FROM conversations WHERE session_id = ? LIMIT 1",
            (session_id,),
        ).fetchone()
    return int(row["id"]) if row else None


def get_most_recent_session() -> tuple[str, int] | None:
    """Return (session_id, conversation_id) for the latest conversation row.

    Used on the very first page load when st.session_state has no session_id
    yet, so we can restore the most recently active chat instead of starting
    a blank slate.
    """
    with _connect() as conn:
        row = conn.execute(
            "SELECT session_id, id FROM conversations ORDER BY id DESC LIMIT 1"
        ).fetchone()
    return (row["session_id"], int(row["id"])) if row else None


def clear_all_history() -> None:
    """Delete every conversation and message — full database reset.

    Triggered by the "Clear Cache" button in the Streamlit sidebar.
    The schema tables are preserved so the app can immediately write new data.
    """
    with _connect() as conn:
        # CASCADE via foreign key removes messages automatically.
        conn.execute("DELETE FROM conversations")
        conn.commit()
