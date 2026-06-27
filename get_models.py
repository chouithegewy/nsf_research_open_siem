import urllib.request
import os
import json
from dotenv import load_dotenv

load_dotenv()
req = urllib.request.Request(
    "http://10.20.10.117:8080/api/models",
    headers={"Authorization": f"Bearer {os.getenv('LLM_API_KEY')}"}
)
try:
    resp = urllib.request.urlopen(req, timeout=10)
    data = json.loads(resp.read().decode())
    print("Models found:", [m.get("id") for m in data.get("data", [])])
except Exception as e:
    print("Error:", e)
