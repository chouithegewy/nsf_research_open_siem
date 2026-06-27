import json
import os
import argparse
import urllib.request
import urllib.error
import uuid
from dotenv import load_dotenv
from concurrent.futures import ThreadPoolExecutor, as_completed

load_dotenv()

# We'll use the local Open WebUI server by default, targeting the massive 70B model
DEFAULT_ENDPOINT = os.getenv("LLM_ENDPOINT", "http://10.20.10.117:8080") + "/api/chat/completions"
DEFAULT_API_KEY = os.getenv("LLM_API_KEY", "")
DEFAULT_MODEL = "meta/llama-3.3-70b"

def query_llm(system_prompt: str, user_prompt: str, endpoint: str, api_key: str, model: str) -> str:
    """Queries the LLM endpoint (OpenAI-compatible) and returns the generated text."""
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ],
        "temperature": 0.2, # Keep temperature low for analytical consistency
        "max_tokens": 500,
        "stream": False,
        "chat_id": f"distill-{uuid.uuid4().hex}"
    }

    req = urllib.request.Request(endpoint, data=json.dumps(payload).encode(), headers=headers)
    
    try:
        with urllib.request.urlopen(req, timeout=300) as response:
            data = json.loads(response.read().decode())
            return data["choices"][0]["message"]["content"].strip()
    except urllib.error.HTTPError as e:
        print(f"Error querying LLM: {e.code} - {e.read().decode('utf-8', 'ignore')}")
        return ""
    except Exception as e:
        print(f"Error querying LLM: {e}")
        return ""

def process_entry(entry: dict, endpoint: str, api_key: str, model: str) -> dict:
    """Processes a single dataset entry by replacing the placeholder with synthetic data."""
    system_prompt = entry["messages"][0]["content"]
    user_prompt = entry["messages"][1]["content"]
    
    generated_summary = query_llm(system_prompt, user_prompt, endpoint, api_key, model)
    
    if generated_summary:
        entry["messages"][2]["content"] = generated_summary
        return entry
    return None

def main():
    parser = argparse.ArgumentParser(description="Generate synthetic ground-truth data for fine-tuning via LLM distillation.")
    parser.add_argument("--input", type=str, default="finetune_dataset.jsonl", help="Input JSONL with placeholders")
    parser.add_argument("--output", type=str, default="distilled_dataset.jsonl", help="Output JSONL with synthetic truths")
    parser.add_argument("--samples", type=int, default=500, help="Number of samples to generate (500 is usually enough for fine-tuning)")
    parser.add_argument("--endpoint", type=str, default=DEFAULT_ENDPOINT, help="OpenAI-compatible API endpoint")
    parser.add_argument("--model", type=str, default=DEFAULT_MODEL, help="Model name to query")
    parser.add_argument("--workers", type=int, default=1, help="Concurrent threads. Keep at 1 if your server can't handle parallel batches.")
    args = parser.parse_args()

    if not os.path.exists(args.input):
        print(f"Error: Could not find {args.input}")
        return

    # Load entries
    entries = []
    with open(args.input, "r") as f:
        for line in f:
            if line.strip():
                entries.append(json.loads(line))

    # Slice to the requested sample size
    target_entries = entries[:args.samples]
    print(f"Loaded {len(entries)} total examples. Distilling ground truths for {len(target_entries)} examples...")
    print(f"Targeting Endpoint: {args.endpoint}")
    print(f"Targeting Model: {args.model}")

    completed_entries = []
    
    # Process sequentially or concurrently depending on args
    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        future_to_entry = {
            executor.submit(process_entry, entry, args.endpoint, DEFAULT_API_KEY, args.model): entry 
            for entry in target_entries
        }
        
        for i, future in enumerate(as_completed(future_to_entry), 1):
            result = future.result()
            if result:
                completed_entries.append(result)
                print(f"[{i}/{len(target_entries)}] Successfully generated summary.")
            else:
                print(f"[{i}/{len(target_entries)}] Failed to generate summary.")

    # Write the completed distilled dataset
    with open(args.output, "w") as f:
        for entry in completed_entries:
            f.write(json.dumps(entry) + "\n")

    print(f"\nDone! Successfully distilled {len(completed_entries)} training examples.")
    print(f"Saved to: {args.output}")

if __name__ == "__main__":
    main()
