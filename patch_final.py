import re

with open("src/honeypot_ai/wazuh_preview.py", "r") as f:
    content = f.read()

# Inject the AI Analyst panel HTML directly into the returned dashboard string
content = content.replace(
    '<section class="grid">',
    '{_ai_summary_panel(llm_summary)}\n    <section class="grid">'
)

with open("src/honeypot_ai/wazuh_preview.py", "w") as f:
    f.write(content)
