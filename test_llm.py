import urllib.request, json, time, os
from dotenv import load_dotenv

load_dotenv()
api_key = os.getenv("LLM_API_KEY")
url = "http://10.20.10.117:8080/api/chat/completions"

headers = {
    "Content-Type": "application/json",
    "Authorization": f"Bearer {api_key}"
}
data = {
    "model": "",
    "messages": [{"role": "user", "content": "Hello!"}]
}

start = time.time()
print("Sending request...")
try:
    req = urllib.request.Request(url, data=json.dumps(data).encode(), headers=headers)
    with urllib.request.urlopen(req, timeout=300) as resp:
        print(f"Success! Took {time.time() - start:.2f}s")
        print(resp.read().decode())
except Exception as e:
    print(f"Error: {e}. Took {time.time() - start:.2f}s")
