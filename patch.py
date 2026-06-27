import re

with open("src/honeypot_ai/wazuh_preview.py", "r") as f:
    content = f.read()

# 1. Add imports
imports = """import threading
import time
import os
from honeypot_ai.llm import LLMClient, LLMConfig
"""
if "from honeypot_ai.llm" not in content:
    content = content.replace("from typing import Any", imports + "from typing import Any", 1)

# 2. Add AI Analyst panel HTML generator
panel_code = """
def _ai_summary_panel(summary: str) -> str:
    if not summary:
        return ""
    return f'''
    <section id="ai-summary-panel" class="panel" style="margin-bottom: 22px; position: relative; overflow: hidden; border: 1px solid rgba(15, 118, 110, 0.3); box-shadow: 0 4px 15px -3px rgba(15, 118, 110, 0.1);">
      <div style="position: absolute; top: 0; left: 0; right: 0; height: 3px; background: linear-gradient(90deg, var(--teal), #06b6d4, var(--teal));"></div>
      <h2 style="margin-top: 4px; color: var(--teal); font-weight: 700; display: flex; align-items: center; gap: 8px;">
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2v20M17 5H9.5a3.5 3.5 0 0 0 0 7h5a3.5 3.5 0 0 1 0 7H6"/></svg>
        Live AI Threat Analyst Summary
      </h2>
      <div style="background: #0f172a; color: #e2e8f0; border-radius: 8px; padding: 20px; margin-top: 14px; font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; font-size: 13.5px; white-space: pre-wrap; line-height: 1.6; border: 1px solid rgba(255, 255, 255, 0.1); box-shadow: inset 0 2px 4px 0 rgba(0, 0, 0, 0.06);">
        {_html(summary)}
      </div>
    </section>
    '''
"""
if "_ai_summary_panel" not in content:
    content = content.replace("def _panel(", panel_code + "\ndef _panel(", 1)

# 3. Add global state and get_live_llm_summary
globals_code = """
_LLM_SUMMARY_CACHE = None
_LLM_LAST_RUN = 0.0
_LLM_THREAD_ACTIVE = False
_LLM_THREAD_STARTED_AT = 0.0
_LLM_LOCK = threading.Lock()

def get_live_llm_summary(events) -> str:
    global _LLM_SUMMARY_CACHE, _LLM_LAST_RUN, _LLM_THREAD_ACTIVE, _LLM_THREAD_STARTED_AT
    now = time.time()
    
    config = LLMConfig()
    try:
        dashboard_timeout = max(1, int(os.getenv("LLM_DASHBOARD_TIMEOUT", "300")))
    except ValueError:
        dashboard_timeout = 300
    config.timeout = min(config.timeout, dashboard_timeout)
    client = LLMClient(config)

    if not client.is_enabled():
        return "AI Analyst is disabled."

    if _LLM_THREAD_ACTIVE:
        if now - _LLM_THREAD_STARTED_AT > dashboard_timeout + 5:
            _LLM_SUMMARY_CACHE = "AI Analyst request exceeded timeout."
            _LLM_THREAD_ACTIVE = False
        return _LLM_SUMMARY_CACHE or "AI Analyst is reviewing live telemetry (this may take a few minutes)..."

    if now - _LLM_LAST_RUN > 30 and events:
        _LLM_LAST_RUN = now
        _LLM_THREAD_STARTED_AT = now
        _LLM_THREAD_ACTIVE = True
        
        # Keep it extremely fast by only sending the last 5 events
        recent_events = sorted(events, key=lambda e: e.get("timestamp") or "", reverse=True)[:5]
        
        def _run_llm_request():
            global _LLM_SUMMARY_CACHE, _LLM_THREAD_ACTIVE
            with _LLM_LOCK:
                try:
                    summary = client.summarize_events(recent_events)
                    _LLM_SUMMARY_CACHE = summary or "AI Analyst did not return a summary."
                except Exception as e:
                    _LLM_SUMMARY_CACHE = f"Error: {e}"
                finally:
                    _LLM_THREAD_ACTIVE = False
                    
        threading.Thread(target=_run_llm_request, daemon=True).start()

    return _LLM_SUMMARY_CACHE or "AI Analyst is preparing..."
"""
if "get_live_llm_summary" not in content:
    content = content.replace("def write_dashboard_preview(", globals_code + "\n\ndef write_dashboard_preview(", 1)

# 4. Inject into HTML layout
if "_ai_summary_panel" not in content and "_dashboard_shell" in content:
    # Need to update _dashboard_shell to accept llm_summary
    pass # Wait, _dashboard_shell doesn't exist in HEAD? Let's check!

with open("src/honeypot_ai/wazuh_preview.py", "w") as f:
    f.write(content)
