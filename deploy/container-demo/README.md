# Honeypot AI Container Demo

This demo starts a small lab with a SIEM enrichment loop, ML scoring loop,
dashboard renderer, LLM bridge, Cowrie SSH honeypot, reverse proxy, and an
attacker container.

The LLM model is not run inside Podman. The `llm-bridge` container forwards
dashboard analyst requests to a private/local LLM endpoint reachable over the
host NetBird VPN, such as Ollama, LM Studio, or Open WebUI.

The lab uses Podman and a Compose-compatible file. Use `podman compose` when
your Podman install has a Compose provider; otherwise substitute
`podman-compose` with the same `-f compose.yaml` argument.

## Start

```bash
cd deploy/container-demo
cp demo.env.example .env
podman compose --env-file .env -f compose.yaml up --build -d siem ml dashboard-renderer dashboard llm-bridge cowrie reverse-proxy
```

Open the dashboard through the reverse proxy:

```text
http://localhost:8888
```

To run the attacker:

```bash
podman compose --env-file .env -f compose.yaml run --rm attacker
```

The attacker container performs a TCP scan against the reverse proxy, probes the
dashboard, attempts SSH logins through the proxy into Cowrie, and appends
deterministic normalized telemetry into the SIEM ingest volume. The deterministic
events make the dashboard update even when an interactive probe times out during
a presentation.

## NetBird LLM

Edit `.env`:

```dotenv
DEMO_LLM_ENABLED=true
DEMO_LLM_ENDPOINT=http://llm-bridge:8080
DEMO_UPSTREAM_LLM_ENDPOINT=http://10.20.10.117:8080
DEMO_LLM_MODEL=meta/llama-3.3-70b
DEMO_LLM_MAX_TOKENS=96
DEMO_LLM_DASHBOARD_TIMEOUT=300
```

Use the endpoint for the desktop running the local LLM server. For LM Studio or
another OpenAI-compatible `/v1` endpoint, set `DEMO_LLM_ENDPOINT` to
`http://llm-bridge:8080/v1` and set `DEMO_UPSTREAM_LLM_ENDPOINT` to the upstream
host base URL without `/v1`. For Open WebUI or any authenticated endpoint, also
set `DEMO_UPSTREAM_LLM_BEARER_TOKEN` or keep `LLM_API_KEY` set in the repo
`.env`, which the Compose file uses as a fallback.

If Podman cannot reach the NetBird peer from a rootless container, verify host
firewall and forwarding rules for Podman bridge traffic to the NetBird
interface. If the LLM is on the same host as Podman, `host.containers.internal`
is usually the right hostname.

## Inspect

```bash
podman compose --env-file .env -f compose.yaml logs -f siem ml dashboard-renderer llm-bridge
podman compose --env-file .env -f compose.yaml exec siem tail -n 20 /data/alerts/wazuh-alerts.ndjson
podman compose --env-file .env -f compose.yaml exec ml tail -n 20 /data/alerts/ml-alerts.ndjson
```

## Reset

```bash
podman compose --env-file .env -f compose.yaml down -v
```
