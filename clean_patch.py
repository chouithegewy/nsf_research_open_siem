import re

with open("src/honeypot_ai/wazuh_preview.py", "r") as f:
    content = f.read()

# 1. Fix API Key passing
api_key_fix = """    from honeypot_ai.llm import LLMClient, LLMConfig
    config = LLMConfig()
    config.bearer_token = os.getenv("LLM_API_KEY", config.bearer_token)
    client = LLMClient(config=config)"""
content = re.sub(
    r'    from honeypot_ai\.llm import LLMClient\n    client = LLMClient\(\)',
    api_key_fix,
    content
)

# 2. Fix Generator Exhaustion
gen_fix = """def render_dashboard_preview(
    events: Iterable[Mapping[str, Any]],
    spec: Mapping[str, Any],
    *,
    refresh_seconds: int = 0,
) -> str:
    events = list(events)"""
content = re.sub(
    r'def render_dashboard_preview\(\n    events: Iterable\[Mapping\[str, Any\]\],\n    spec: Mapping\[str, Any\],\n    \*,\n    refresh_seconds: int = 0,\n\) -> str:',
    gen_fix,
    content
)

# 3. Fix Cache Deadlock
cache_fix = """    changed = False
    if current_file_states != _LAST_PREVIEW_STATE.get("file_states"):
        changed = True
    
    # Force a redraw if the background LLM thread finally finished its work
    if _LLM_SUMMARY_CACHE != _LAST_PREVIEW_STATE.get("llm_summary_cache"):
        changed = True
        _LAST_PREVIEW_STATE["llm_summary_cache"] = _LLM_SUMMARY_CACHE

    if not changed and _LAST_PREVIEW_STATE.get("output_state"):
        return _LAST_PREVIEW_STATE["output_state"]
"""
content = re.sub(
    r'    changed = False\n    if current_file_states != _LAST_PREVIEW_STATE\.get\("file_states"\):\n        changed = True\n    if _LLM_SUMMARY_CACHE != _LAST_PREVIEW_STATE\.get\("llm_summary_cache"\):\n        changed = True\n\n    if not changed and _LAST_PREVIEW_STATE\["output_state"\] is not None and _LLM_SUMMARY_CACHE == _LAST_PREVIEW_STATE\["llm_summary_cache"\]:\n        return _LAST_PREVIEW_STATE\["result"\]\n    elif _LAST_PREVIEW_STATE\.get\("llm_summary_cache"\) is None and _LLM_SUMMARY_CACHE is not None:\n        changed = True\n\n    output = Path\([^)]+\)',
    cache_fix + '\n    output = Path(output_path)',
    content,
    flags=re.DOTALL
)

# Wait, the `write_dashboard_preview` logic at HEAD actually is:
#     changed = False
#     if current_file_states != _LAST_PREVIEW_STATE.get("file_states"):
#         changed = True
#     if _LLM_SUMMARY_CACHE != _LAST_PREVIEW_STATE.get("llm_summary_cache"):
#         changed = True
# 
#     output = Path(output_path)
#     if not changed and output.exists():
#         return current_file_states
# Let's write a safer regex for part 3.
