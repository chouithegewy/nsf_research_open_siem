import json
import argparse
import os

# The exact system prompt the dashboard uses
SYSTEM_PROMPT = (
    "You are a cybersecurity AI analyst. The user will provide a list of "
    "recent eBPF events from a honeypot. Summarize what the attacker is "
    "trying to do. Keep your summary concise, technical, and actionable."
)

def clean_event(event: dict) -> dict:
    """Removes bulky/unnecessary metadata to optimize context window size."""
    bulky_keys = {
        "kexAlgs", "keyAlgs", "encCS", "macCS", "compCS", "langCS",
        "hasshAlgorithms", "kexAlgorithms", "payload", "packet",
        "payload_printable", "raw"
    }
    return {k: v for k, v in event.items() if k not in bulky_keys}

def generate_dataset(input_path: str, output_path: str, batch_size: int = 5):
    if not os.path.exists(input_path):
        print(f"Error: Input file {input_path} not found.")
        return

    # Load all events
    events = []
    with open(input_path, "r") as f:
        for line in f:
            if not line.strip():
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                pass

    # Sort events chronologically (assuming they have a timestamp)
    events.sort(key=lambda x: x.get("timestamp", ""))

    dataset_entries = []
    
    # Process in batches
    for i in range(0, len(events), batch_size):
        batch = events[i : i + batch_size]
        cleaned_batch = [clean_event(e) for e in batch]
        
        # Convert batch to the exact string format used by the live dashboard
        events_text = "\n".join(json.dumps(e, separators=(",", ":")) for e in cleaned_batch)
        user_prompt = f"Analyze these eBPF events:\n{events_text}"

        # Create the standard fine-tuning conversation structure
        entry = {
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
                {
                    "role": "assistant", 
                    "content": "<PLACEHOLDER: Insert the ideal, expert summary of these events here. Or use a script to query an API like GPT-4o or Llama-3-70B to generate synthetic ground-truth summaries.>"
                }
            ]
        }
        dataset_entries.append(entry)

    # Write to standard JSONL format
    with open(output_path, "w") as f:
        for entry in dataset_entries:
            f.write(json.dumps(entry) + "\n")
            
    print(f"Successfully generated {len(dataset_entries)} training examples.")
    print(f"Dataset saved to: {output_path}")
    print("\nNext Steps:")
    print("1. Review the generated .jsonl file.")
    print("2. Replace the '<PLACEHOLDER>' text with actual ideal summaries (either manually or via an API script).")
    print("3. Use the finished JSONL file to fine-tune a fast 1.5B/3B model using Unsloth or Axolotl!")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Extract eBPF events into an LLM fine-tuning dataset.")
    parser.add_argument("--input", type=str, default="build/wazuh-live/alerts.ndjson", help="Path to input ndjson events file")
    parser.add_argument("--output", type=str, default="finetune_dataset.jsonl", help="Path to output jsonl dataset")
    parser.add_argument("--batch-size", type=int, default=5, help="Number of events per context window")
    args = parser.parse_args()

    generate_dataset(args.input, args.output, args.batch_size)
