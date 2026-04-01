"""Tests for vigil core functionality.

Run with: python -m pytest tests/ -v
"""

import hashlib
import json
import os
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

from vigil.config import ConfigError, load_config
from vigil.alerts import send_alert
from vigil.monitors.file_integrity import _hash_file, _scan_directory, _check_changes
from vigil.monitors.crypto import _mark_seen, _seen_set, _seen_order


# --- Config tests ---

class TestConfig:
    def test_missing_file_raises(self, tmp_path):
        with pytest.raises(ConfigError, match="not found"):
            load_config(str(tmp_path / "nonexistent.yaml"))

    def test_empty_file_raises(self, tmp_path):
        cfg = tmp_path / "config.yaml"
        cfg.write_text("")
        with pytest.raises(ConfigError, match="empty"):
            load_config(str(cfg))

    def test_missing_alert_type_raises(self, tmp_path):
        cfg = tmp_path / "config.yaml"
        cfg.write_text(yaml.dump({"monitors": {"crypto": {"enabled": True}}}))
        with pytest.raises(ConfigError, match="alert.type"):
            load_config(str(cfg))

    def test_invalid_alert_type_raises(self, tmp_path):
        cfg = tmp_path / "config.yaml"
        data = {
            "alert": {"type": "pigeonmail"},
            "monitors": {"crypto": {"enabled": True, "wallets": {"eth": ["0x123"]}, "thresholds": {"large_transfer_usd": 5000}}},
        }
        cfg.write_text(yaml.dump(data))
        with pytest.raises(ConfigError, match="Invalid alert.type"):
            load_config(str(cfg))

    def test_no_monitors_enabled_raises(self, tmp_path):
        cfg = tmp_path / "config.yaml"
        data = {
            "alert": {"type": "stdout"},
            "monitors": {"crypto": {"enabled": False}},
        }
        cfg.write_text(yaml.dump(data))
        with pytest.raises(ConfigError, match="No monitors enabled"):
            load_config(str(cfg))

    def test_valid_crypto_config(self, tmp_path):
        cfg = tmp_path / "config.yaml"
        data = {
            "alert": {"type": "stdout"},
            "monitors": {
                "crypto": {
                    "enabled": True,
                    "wallets": {"eth": ["0xabc"]},
                    "thresholds": {"large_transfer_usd": 1000},
                }
            },
        }
        cfg.write_text(yaml.dump(data))
        result = load_config(str(cfg))
        assert result["monitors"]["crypto"]["enabled"] is True

    def test_valid_fim_config(self, tmp_path):
        cfg = tmp_path / "config.yaml"
        data = {
            "alert": {"type": "json"},
            "monitors": {
                "file_integrity": {
                    "enabled": True,
                    "watch_paths": [str(tmp_path)],
                }
            },
        }
        cfg.write_text(yaml.dump(data))
        result = load_config(str(cfg))
        assert result["monitors"]["file_integrity"]["enabled"] is True


# --- Alert tests ---

class TestAlerts:
    def test_stdout_alert(self, capsys):
        config = {"alert": {"type": "stdout"}}
        send_alert("test message", config, source="test")
        output = capsys.readouterr().out
        assert "test message" in output
        assert "[test]" in output

    def test_json_alert(self, capsys):
        config = {"alert": {"type": "json"}}
        send_alert("json test", config, source="crypto")
        output = capsys.readouterr().out
        data = json.loads(output)
        assert data["alert"] == "json test"
        assert data["source"] == "crypto"
        assert "timestamp" in data

    def test_slack_alert_failure_falls_back(self, capsys):
        config = {"alert": {"type": "slack", "webhook_url": "http://localhost:99999/bad"}}
        send_alert("should fallback", config, source="test")
        output = capsys.readouterr().out
        assert "webhook failed" in output
        assert "should fallback" in output


# --- File integrity tests ---

class TestFileIntegrity:
    def test_hash_file(self, tmp_path):
        f = tmp_path / "test.txt"
        f.write_text("hello world")
        expected = hashlib.sha256(b"hello world").hexdigest()
        assert _hash_file(str(f)) == expected

    def test_hash_nonexistent_returns_none(self):
        assert _hash_file("/nonexistent/path/file.txt") is None

    def test_scan_directory(self, tmp_path):
        (tmp_path / "a.txt").write_text("aaa")
        (tmp_path / "b.txt").write_text("bbb")
        sub = tmp_path / "subdir"
        sub.mkdir()
        (sub / "c.txt").write_text("ccc")
        result = _scan_directory(str(tmp_path))
        assert len(result) == 3

    def test_check_changes_detects_new(self):
        baseline = {"a.txt": "hash1"}
        current = {"a.txt": "hash1", "b.txt": "hash2"}
        new, removed, modified = _check_changes(baseline, current)
        assert new == ["b.txt"]
        assert removed == []
        assert modified == []

    def test_check_changes_detects_removed(self):
        baseline = {"a.txt": "hash1", "b.txt": "hash2"}
        current = {"a.txt": "hash1"}
        new, removed, modified = _check_changes(baseline, current)
        assert new == []
        assert removed == ["b.txt"]
        assert modified == []

    def test_check_changes_detects_modified(self):
        baseline = {"a.txt": "hash1"}
        current = {"a.txt": "hash2"}
        new, removed, modified = _check_changes(baseline, current)
        assert new == []
        assert removed == []
        assert modified == ["a.txt"]

    def test_check_no_changes(self):
        baseline = {"a.txt": "hash1"}
        current = {"a.txt": "hash1"}
        new, removed, modified = _check_changes(baseline, current)
        assert new == [] and removed == [] and modified == []


# --- Crypto dedup tests ---

class TestCryptoDedup:
    def setup_method(self):
        """Clear dedup state between tests."""
        _seen_set.clear()
        _seen_order.clear()

    def test_first_seen_returns_false(self):
        assert _mark_seen("tx_001") is False

    def test_duplicate_returns_true(self):
        _mark_seen("tx_001")
        assert _mark_seen("tx_001") is True

    def test_eviction_at_maxlen(self):
        # Fill to capacity
        for i in range(2000):
            _mark_seen(f"tx_{i:05d}")
        assert len(_seen_set) == 2000
        # Adding one more should evict the oldest
        _mark_seen("tx_new")
        assert "tx_00000" not in _seen_set
        assert "tx_new" in _seen_set
        assert len(_seen_set) == 2000
