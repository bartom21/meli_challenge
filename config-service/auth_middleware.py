import os
import time
import hashlib
import hmac
from fastapi import Header, HTTPException
from dotenv import load_dotenv

load_dotenv()
SECRET_KEY = os.getenv("CONFIG_SERVICE_API_KEY")  # Shared HMAC secret
HMAC_EXPIRATION_SECONDS = 60  # Allow requests up to 60 seconds old

def verify_hmac_signature(signature: str, timestamp: str, request_id: str):
    """Validates an incoming HMAC signature."""
    if not signature or not timestamp or not request_id:
        raise HTTPException(status_code=401, detail="Missing authentication headers")

    # Validate timestamp (prevent replay attacks)
    current_time = int(time.time())
    request_time = int(timestamp)

    if abs(current_time - request_time) > HMAC_EXPIRATION_SECONDS:
        raise HTTPException(status_code=401, detail="Request expired")

    # Recompute the expected signature
    message = f"{timestamp}:{request_id}"
    expected_signature = hmac.new(SECRET_KEY.encode(), message.encode(), hashlib.sha256).hexdigest()

    if not hmac.compare_digest(signature, expected_signature):
        raise HTTPException(status_code=401, detail="Invalid HMAC signature")

    return True  # Signature is valid
