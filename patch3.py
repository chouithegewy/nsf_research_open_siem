import re

with open("src/honeypot_ai/wazuh_preview.py", "r") as f:
    content = f.read()

replacement = """
    changed = False
    for path, (mtime, size) in current_file_states.items():
        old_mtime, old_size = _LAST_PREVIEW_STATE["file_states"].get(path, (0.0, 0))
        if mtime != old_mtime or size != old_size:
            changed = True
            break

    # If the LLM cache was updated by the background thread, force a redraw
    if _LLM_SUMMARY_CACHE != _LAST_PREVIEW_STATE.get("llm_summary_cache"):
        changed = True
        _LAST_PREVIEW_STATE["llm_summary_cache"] = _LLM_SUMMARY_CACHE

    if not changed and _LAST_PREVIEW_STATE.get("output_state"):
        return current_file_states
"""

content = re.sub(r'    changed = False\n.*?if not changed and _LLM_SUMMARY_CACHE == _LAST_PREVIEW_STATE\["llm_summary_cache"\]:\n        return current_file_states', replacement, content, flags=re.DOTALL)

with open("src/honeypot_ai/wazuh_preview.py", "w") as f:
    f.write(content)
