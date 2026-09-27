"""List vMaaS models using credentials supplied through environment variables."""
import os
import sys

import requests
from dotenv import load_dotenv

load_dotenv()
api_key = os.getenv("VMAAS_API_KEY", "").strip()
if not api_key:
    sys.exit("Set VMAAS_API_KEY in the environment (or the project .env file).")

endpoint = os.getenv("VMAAS_MODELS_URL", "https://aiplatform.viettelidc.com.vn/apis/v2/models")
response = requests.get(endpoint, headers={"Authorization": f"Bearer {api_key}"}, timeout=(10, 30))
response.raise_for_status()
print(response.json())
