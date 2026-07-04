"""
HTTP client for the Open Claw orchestrator (Node.js, port 3000).

All network calls to the backend are centralised here so that individual
Streamlit pages never import `requests` directly.  Error handling converts
network failures into safe return values — the UI never crashes on a
temporarily unavailable backend.
"""

import requests

from config import API_BASE_URL

# Timeout for the live-traffic endpoint.  Should be fast; the backend reads RAM.
_MEMORY_TIMEOUT_S: int = 5

# Timeout for the AI chat endpoint.  The Llama 3.1 ReAct loop (tool calls +
# inference) can take 30–90 seconds, so we give it a generous 120-second budget.
_CHAT_TIMEOUT_S: int = 120


def get_memory_events() -> list[dict]:
    """Fetch the current contents of the orchestrator's circular buffer.

    Returns:
        A list of TcpEvent dicts (keys: pid, comm, daddr, dport, ip_address).
        Returns an empty list if the backend is unreachable or returns an error.
    """
    url = f"{API_BASE_URL}/memory"
    try:
        response = requests.get(url, timeout=_MEMORY_TIMEOUT_S)
        response.raise_for_status()
        data = response.json()
        # Guard against an unexpected non-list payload.
        return data if isinstance(data, list) else []
    except requests.exceptions.ConnectionError:
        # Orchestrator not yet started — silently return empty so the UI stays up.
        return []
    except requests.exceptions.Timeout:
        print(f"[orchestrator_client] GET /memory timed out after {_MEMORY_TIMEOUT_S}s")
        return []
    except Exception as exc:  # noqa: BLE001
        print(f"[orchestrator_client] GET /memory failed: {exc}")
        return []


def post_chat(question: str, history: list | None = None) -> str:
    """Send a natural-language question to the AI agent and return its Markdown report.

    The orchestrator will:
      1. Freeze a snapshot of the current network buffer.
      2. Run the deterministic Extractor → Executor → Reporter pipeline.
      3. Return a Markdown-formatted report.

    Args:
        question: The user's free-text question about network activity.
        history:  Optional list of previous messages in the conversation,
                  each a dict with "role" ("user"|"assistant") and "content".
                  Passed to the Reporter LLM for conversational context.
                  The caller is responsible for limiting the list length.

    Returns:
        A Markdown string containing the agent's report, or a human-readable
        error message if the request fails.
    """
    url = f"{API_BASE_URL}/api/chat"
    payload: dict = {
        "question": question,
        "history":  (history or [])[-6:],   # cap at last 6 messages for safety
    }

    try:
        response = requests.post(url, json=payload, timeout=_CHAT_TIMEOUT_S)
        response.raise_for_status()
        data = response.json()

        # The orchestrator wraps the report in { "report": "..." }.
        report = data.get("report", "")
        if not isinstance(report, str) or not report.strip():
            return "⚠️ The agent returned an empty report. The network buffer may be empty."
        return report

    except requests.exceptions.ConnectionError:
        return (
            "❌ **Connection failed.** "
            "Make sure the orchestrator is running on `http://localhost:3000`."
        )
    except requests.exceptions.Timeout:
        return (
            f"⏱️ **Request timed out** after {_CHAT_TIMEOUT_S} seconds. "
            "The AI agent is taking longer than expected. Try again or simplify your question."
        )
    except requests.exceptions.HTTPError as exc:
        status = exc.response.status_code if exc.response is not None else "unknown"
        return f"❌ **Orchestrator returned HTTP {status}.** Check server logs for details."
    except Exception as exc:  # noqa: BLE001
        return f"❌ **Unexpected error:** {exc}"
