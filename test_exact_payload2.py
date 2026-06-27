import urllib.request
import os
import json

api_key = "lm-studio"
url = "http://10.20.10.117:8081/v1/chat/completions"

headers = {
    "Content-Type": "application/json",
    "Authorization": f"Bearer {api_key}"
}
payload = {
    "model": "loaded-model",
    "messages": [
        {"role": "system", "content": "You are a test AI."},
        {"role": "user", "content": "Say hello!"},
    ],
    "temperature": 0.3,
    "max_tokens": 1024,
}

try:
    req = urllib.request.Request(url, data=json.dumps(payload).encode(), headers=headers)
    with urllib.request.urlopen(req, timeout=300) as resp:
        print(resp.read().decode())
except urllib.error.HTTPError as e:
    print("HTTP Error:", e.code)
    print("Body:", e.read().decode())
except Exception as e:
    print("Error:", e)
