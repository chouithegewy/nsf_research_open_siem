import re

with open("src/honeypot_ai/wazuh_preview.py", "r") as f:
    content = f.read()

# 1. Update _dashboard_shell signature
content = content.replace(
    'def _dashboard_shell(model: dict[str, Any], refresh_note: str = "") -> str:',
    'def _dashboard_shell(model: dict[str, Any], llm_summary: str = "", refresh_note: str = "") -> str:'
)

# 2. Inject into HTML
content = content.replace(
    '<section class="grid">',
    '{_ai_summary_panel(llm_summary)}\n    <section class="grid">'
)

# 3. Call get_live_llm_summary in write_dashboard_preview
content = content.replace(
    'body = _dashboard_shell(model, refresh_note=refresh_note)',
    'llm_summary = get_live_llm_summary(model.get("recent_events", []))\n    body = _dashboard_shell(model, llm_summary=llm_summary, refresh_note=refresh_note)'
)

with open("src/honeypot_ai/wazuh_preview.py", "w") as f:
    f.write(content)
