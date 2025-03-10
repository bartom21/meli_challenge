import secrets
import time

DEFAULT_TTL_DAYS = 90  # Default time-to-live (TTL) in days

def generate_api_key(prefix: str = "API", length: int = 32, ttl_days: int = DEFAULT_TTL_DAYS) -> str:
    """
    Generates a cryptographically secure API key with an expiration timestamp.
    
    Args:
        prefix (str): Optional prefix for identifying key type (e.g., "API").
        length (int): Number of bytes for the random part (default: 32).
        ttl_days (int): Time-to-live in days before expiration.

    Returns:
        str: The generated API key and expiration timestamp.
    """
    random_bytes = secrets.token_bytes(length)  # Generate secure random bytes
    key = secrets.token_hex(length)  # Convert to hex
    expiration_time = int(time.time()) + (ttl_days * 86400)  # Convert TTL to seconds

    full_key = f"{prefix}_{key}"  # Formatted API key

    return full_key, expiration_time

if __name__ == "__main__":
    api_key, expiration = generate_api_key()
    print(f"Generated API Key: {api_key}")
    print(f"Expires At: {time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(expiration))}")
