import os
import requests
from dotenv import load_dotenv
from auth_utils import create_auth_headers  # Import HMAC utilities

load_dotenv()
CONFIG_URL = os.getenv("CONFIG_SERVICE_URL") 

def fetch_config():
    """Fetches the network configuration from config-service using HMAC authentication."""
    headers = create_auth_headers()  # Generate secure authentication headers
    response = requests.get(CONFIG_URL, headers=headers)

    if response.status_code == 200:
        return response.text  # Return the raw configuration file

    raise Exception(f"Failed to fetch configuration: {response.status_code} - {response.text}")
