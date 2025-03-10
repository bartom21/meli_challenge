import os
import time
import hashlib
import hmac
from dotenv import load_dotenv

load_dotenv()
SECRET_KEY = os.getenv("ANALYSIS_SERVICE_API_KEY")  # Shared HMAC secret

def generate_hmac_signature(message: str) -> str:
    """Creates an HMAC SHA-256 signature."""
    return hmac.new(SECRET_KEY.encode(), message.encode(), hashlib.sha256).hexdigest()

def create_auth_headers():
    """Generates HMAC-authenticated headers for secure API calls."""
    timestamp = str(int(time.time()))  # Current timestamp (UNIX epoch)
    request_id = os.urandom(16).hex()  # Unique request identifier
    message = f"{timestamp}:{request_id}"
    
    signature = generate_hmac_signature(message)

    return {
        "X-Request-ID": request_id,
        "X-Timestamp": timestamp,
        "X-Signature": signature
    }
