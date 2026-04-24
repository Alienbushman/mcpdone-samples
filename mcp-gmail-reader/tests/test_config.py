"""Tests for config loading + validation."""
from __future__ import annotations

from pathlib import Path

import pytest

from mcp_gmail_reader.config import Config, ConfigError, load_config


# --- Config validation ---


def test_config_accepts_valid_inputs() -> None:
    c = Config(
        email="a@gmail.com",
        app_password="abcdefghijklmnop",
        label="mcpdone-inbox",
    )
    assert c.email == "a@gmail.com"
    assert c.imap_host == "imap.gmail.com"
    assert c.imap_port == 993


def test_config_accepts_app_password_with_spaces() -> None:
    # Google displays them as 4 groups of 4 — strip before validation
    c = Config(
        email="a@gmail.com",
        app_password="abcd efgh ijkl mnop",
        label="inbox",
    )
    # The spaces are stripped at load_config time; Config dataclass itself
    # accepts either. Regex matches stripped form.
    assert c.app_password.replace(" ", "") == "abcdefghijklmnop"


def test_config_rejects_bad_email() -> None:
    with pytest.raises(ConfigError, match="does not look like an email"):
        Config(email="no-at-sign", app_password="abcdefghijklmnop", label="x")


def test_config_rejects_short_password() -> None:
    with pytest.raises(ConfigError, match="App Password"):
        Config(email="a@b.com", app_password="short", label="x")


def test_config_rejects_reserved_label() -> None:
    with pytest.raises(ConfigError, match="reserved"):
        Config(email="a@b.com", app_password="abcdefghijklmnop", label="[Gmail]/All Mail")


def test_config_rejects_bad_port() -> None:
    with pytest.raises(ConfigError, match="out of range"):
        Config(
            email="a@b.com",
            app_password="abcdefghijklmnop",
            label="inbox",
            imap_port=99999,
        )


# --- load_config via env + .env file ---


def test_load_config_reads_env(monkeypatch) -> None:
    monkeypatch.setenv("GMAIL_ADDRESS", "a@gmail.com")
    monkeypatch.setenv("GMAIL_APP_PASSWORD", "abcdefghijklmnop")
    monkeypatch.setenv("GMAIL_LABEL", "inbox")
    cfg = load_config()
    assert cfg.email == "a@gmail.com"
    assert cfg.label == "inbox"


def test_load_config_strips_password_spaces(monkeypatch) -> None:
    monkeypatch.setenv("GMAIL_ADDRESS", "a@gmail.com")
    monkeypatch.setenv("GMAIL_APP_PASSWORD", "abcd efgh ijkl mnop")
    monkeypatch.setenv("GMAIL_LABEL", "inbox")
    cfg = load_config()
    assert cfg.app_password == "abcdefghijklmnop"


def test_load_config_missing_raises(monkeypatch) -> None:
    monkeypatch.delenv("GMAIL_ADDRESS", raising=False)
    monkeypatch.delenv("GMAIL_APP_PASSWORD", raising=False)
    monkeypatch.delenv("GMAIL_LABEL", raising=False)
    with pytest.raises(ConfigError, match="Missing required"):
        load_config(env_file=Path("/does/not/exist"))


def test_load_config_honours_optional_overrides(monkeypatch) -> None:
    monkeypatch.setenv("GMAIL_ADDRESS", "a@gmail.com")
    monkeypatch.setenv("GMAIL_APP_PASSWORD", "abcdefghijklmnop")
    monkeypatch.setenv("GMAIL_LABEL", "inbox")
    monkeypatch.setenv("IMAP_PORT", "143")
    monkeypatch.setenv("IMAP_HOST", "other.example.com")
    monkeypatch.setenv("DRAFTS_FOLDER", "Drafts")
    cfg = load_config()
    assert cfg.imap_port == 143
    assert cfg.imap_host == "other.example.com"
    assert cfg.drafts_folder == "Drafts"


def test_load_config_rejects_bad_port(monkeypatch) -> None:
    monkeypatch.setenv("GMAIL_ADDRESS", "a@gmail.com")
    monkeypatch.setenv("GMAIL_APP_PASSWORD", "abcdefghijklmnop")
    monkeypatch.setenv("GMAIL_LABEL", "inbox")
    monkeypatch.setenv("IMAP_PORT", "not-a-number")
    with pytest.raises(ConfigError, match="must be an integer"):
        load_config()
