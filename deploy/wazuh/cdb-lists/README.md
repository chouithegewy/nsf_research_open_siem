# Wazuh CDB Lists for MISP Indicators

Generate these lists from MISP with:

```bash
PYTHONPATH=src python3 -m honeypot_ai misp-pull \
  --misp-url https://misp.example \
  --misp-key "$MISP_API_KEY" \
  --output-dir deploy/wazuh/cdb-lists/generated
```

Copy the generated files into the Wazuh manager list directory, for example:

- `misp-ip`
- `misp-domain`
- `misp-hash`
- `misp-url`

The sample rules in `deploy/wazuh/rules/honeypot-ai-rules.xml` reference the
runtime paths `etc/lists/misp-ip`, `etc/lists/misp-domain`, and
`etc/lists/misp-hash`.
