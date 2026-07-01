# Central configuration for the Open Claw UI layer.
# All tunable constants live here so individual pages never hard-code values.

# Base URL of the Node.js orchestrator HTTP server.
API_BASE_URL: str = "http://localhost:3000"

# How often the traffic monitor table refreshes, in milliseconds.
TRAFFIC_REFRESH_INTERVAL_MS: int = 2000

# Maximum number of rows shown in the live traffic table at any one time.
# Keeps the UI responsive even when the circular buffer is fully saturated.
MAX_DISPLAYED_EVENTS: int = 200
