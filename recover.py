import json
import sys

log_path = "/home/david/.gemini/antigravity-cli/brain/6f8587ce-cbfb-4a87-827e-74d3f65a9af7/.system_generated/logs/transcript_full.jsonl"

edits = []

try:
    with open(log_path, "r") as f:
        for line in f:
            if "wazuh_preview.py" in line:
                data = json.loads(line)
                if data.get("type") == "PLANNER_RESPONSE":
                    for tc in data.get("tool_calls", []):
                        if tc.get("name") in ["replace_file_content", "multi_replace_file_content"]:
                            args = tc.get("args", {})
                            if "wazuh_preview.py" in args.get("TargetFile", ""):
                                edits.append(tc)
                
    print(f"Found {len(edits)} code edits to wazuh_preview.py")
    
    with open("recovered_edits.json", "w") as f:
        json.dump(edits, f, indent=2)
    print("Saved to recovered_edits.json")

except Exception as e:
    print(f"Error: {e}")
