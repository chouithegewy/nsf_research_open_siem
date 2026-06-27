from __future__ import annotations

import json
import unittest
from unittest.mock import MagicMock, patch
from pathlib import Path
from tempfile import TemporaryDirectory

from honeypot_ai.cli import main
from honeypot_ai.llm import LLMClient, LLMConfig


class LLMTests(unittest.TestCase):
    @patch.dict("os.environ", {}, clear=True)
    def test_defaults_use_netbird_local_desktop_model(self) -> None:
        config = LLMConfig()
        self.assertEqual(config.endpoint, "http://10.20.10.117:8080")
        self.assertEqual(config.model, "qwen/qwen3.5-9b")

    @patch.dict("os.environ", {
        "LLM_ENDPOINT": "http://test-server:1234",
        "LLM_BEARER_TOKEN": "test-token",
        "LLM_MODEL": "test-model",
        "LLM_ENABLED": "true",
        "LLM_TIMEOUT": "30"
    })
    def test_config_from_env(self) -> None:
        config = LLMConfig()
        self.assertEqual(config.endpoint, "http://test-server:1234")
        self.assertEqual(config.bearer_token, "test-token")
        self.assertEqual(config.model, "test-model")
        self.assertTrue(config.enabled)
        self.assertEqual(config.timeout, 30)

    @patch("urllib.request.urlopen")
    @patch("honeypot_ai.llm.LLMClient._detect_api_type")
    def test_client_list_models(self, mock_detect: MagicMock, mock_urlopen: MagicMock) -> None:
        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps({
            "data": [
                {"id": "model-1", "name": "Model One"},
                {"id": "model-2", "name": "Model Two"}
            ]
        }).encode("utf-8")
        mock_urlopen.return_value.__enter__.return_value = mock_response

        client = LLMClient(LLMConfig(bearer_token="key", enabled=True))
        models = client.list_models()
        self.assertEqual(len(models), 2)
        self.assertEqual(models[0]["id"], "model-1")

    @patch("urllib.request.urlopen")
    @patch("honeypot_ai.llm.LLMClient._detect_api_type")
    def test_client_summarize_events(self, mock_detect: MagicMock, mock_urlopen: MagicMock) -> None:
        mock_models_resp = MagicMock()
        mock_models_resp.__enter__.return_value.read.return_value = json.dumps({
            "data": [{"id": "auto-model"}]
        }).encode("utf-8")

        mock_completions_resp = MagicMock()
        mock_completions_resp.__enter__.return_value.read.return_value = json.dumps({
            "choices": [{
                "message": {
                    "role": "assistant",
                    "content": "This is a summary of the activity."
                }
            }]
        }).encode("utf-8")

        mock_urlopen.side_effect = [
            mock_models_resp,
            mock_completions_resp
        ]

        client = LLMClient(LLMConfig(bearer_token="key", enabled=True))
        summary = client.summarize_events([{"event": "test"}])
        self.assertEqual(summary, "This is a summary of the activity.")

    def test_private_endpoint_enabled_without_token(self) -> None:
        client = LLMClient(LLMConfig(endpoint="http://10.20.10.117:8080", enabled=True))
        self.assertTrue(client.is_enabled())

    def test_public_endpoint_disabled_even_with_token(self) -> None:
        client = LLMClient(
            LLMConfig(
                endpoint="https://example.com/v1",
                bearer_token="not-used",
                enabled=True,
            )
        )
        self.assertFalse(client.is_enabled())

    def test_public_endpoint_models_are_not_loaded(self) -> None:
        client = LLMClient(
            LLMConfig(
                endpoint="https://example.com/v1",
                bearer_token="not-used",
                enabled=True,
            )
        )
        self.assertEqual(client.list_models(), [])

    @patch("honeypot_ai.llm.LLMClient.summarize_events")
    @patch("honeypot_ai.llm.LLMClient.is_enabled")
    def test_cli_llm_summarize(self, mock_is_enabled: MagicMock, mock_summarize: MagicMock) -> None:
        mock_is_enabled.return_value = True
        mock_summarize.return_value = "LLM Threat Summary content"

        with TemporaryDirectory() as tmp_dir:
            input_file = Path(tmp_dir) / "events.ndjson"
            input_file.write_text(json.dumps({"event_type": "login", "host": "srv1"}) + "\n")

            output_file = Path(tmp_dir) / "summary.txt"

            status = main([
                "llm-summarize",
                "--output", str(output_file),
                str(input_file)
            ])

            self.assertEqual(status, 0)
            self.assertEqual(output_file.read_text().strip(), "LLM Threat Summary content")
            mock_summarize.assert_called_once()

    @patch("honeypot_ai.llm.LLMClient.summarize_events")
    @patch("honeypot_ai.llm.LLMClient.is_enabled")
    def test_cli_analyze_wires_llm(self, mock_is_enabled: MagicMock, mock_summarize: MagicMock) -> None:
        mock_is_enabled.return_value = True
        mock_summarize.return_value = "Mocked LLM threat report details"

        import io
        import contextlib
        stdout = io.StringIO()
        with TemporaryDirectory() as tmp_dir:
            input_file = Path(tmp_dir) / "events.ndjson"
            input_file.write_text(json.dumps({
                "source": "cowrie",
                "event_type": "login",
                "timestamp": "2026-06-23T15:00:00Z",
                "username": "admin",
                "password": "password"
            }) + "\n")

            with contextlib.redirect_stdout(stdout):
                status = main([
                    "analyze",
                    "--format", "markdown",
                    str(input_file)
                ])

            self.assertEqual(status, 0)
            output = stdout.getvalue()
            self.assertIn("## LLM Threat Summary", output)
            self.assertIn("Mocked LLM threat report details", output)
            mock_summarize.assert_called_once()
