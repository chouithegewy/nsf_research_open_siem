import urllib.request
import os
import json
from dotenv import load_dotenv

load_dotenv()
api_key = os.getenv("LLM_API_KEY")
url = "http://10.20.10.117:8080/api/chat/completions"

headers = {
    "Content-Type": "application/json",
    "Authorization": f"Bearer {api_key}"
}
data = {
    "model": "qwen/qwen3.5-9b",
    "messages": [{"role": "system", "content": "You are a test AI."}, {"role": "user", "content": "Say hello!"}],
    "chat_id": "test"
}

try:
    req = urllib.request.Request(url, data=json.dumps(data).encode(), headers=headers)
    with urllib.request.urlopen(req, timeout=300) as resp:
        print(resp.read().decode())
except urllib.error.HTTPError as e:
    print("HTTP Error:", e.code)
    print("Body:", e.read().decode())
except Exception as e:
    print("Error:", e)
