from fastapi import FastAPI
from fastapi.responses import PlainTextResponse

app = FastAPI()

# Hardcoded configuration (could be read from a file)
MOCK_CONFIG = """
hostname Router1
username admin privilege 15 password 0 weakpass123
snmp-server community public RO
"""

@app.get("/config", response_class=PlainTextResponse)
def get_config():
    """Serve the network config as plain text."""
    return MOCK_CONFIG
