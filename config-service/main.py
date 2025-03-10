from fastapi import FastAPI, Depends, Header
from auth_middleware import verify_hmac_signature  # Import middleware

app = FastAPI()

# Hardcoded configuration (could be read from a file)
MOCK_CONFIG = """
hostname Router1
username admin privilege 15 password 0 weakpass123
snmp-server community public RO
"""

def auth_dependency(
    x_signature: str = Header(None),
    x_timestamp: str = Header(None),
    x_request_id: str = Header(None)
):
    """Wrapper function to pass headers to verify_hmac_signature."""
    return verify_hmac_signature(x_signature, x_timestamp, x_request_id)

@app.get("/config")
def get_config(_: bool = Depends(auth_dependency)):  # Use wrapper function
    """Return the network configuration if API Key is valid."""
    return MOCK_CONFIG
