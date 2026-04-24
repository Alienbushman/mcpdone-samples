"""Tests for scope enforcement + label selection."""
from __future__ import annotations

import pytest

from mcp_gmail_reader.client import ScopeViolation, ensure_label_scope, select_label


def test_ensure_label_scope_passes_when_match() -> None:
    # Should not raise
    ensure_label_scope("mcpdone-inbox", "mcpdone-inbox")


def test_ensure_label_scope_raises_on_mismatch() -> None:
    with pytest.raises(ScopeViolation, match="Refusing to operate"):
        ensure_label_scope("personal", "mcpdone-inbox")


def test_select_label_success(fake_imap) -> None:
    fake_imap.existing_labels.add("test-inbox")
    select_label(fake_imap, "test-inbox")
    assert fake_imap.selected == "test-inbox"
    assert fake_imap.select_readonly is True


def test_select_label_readwrite_option(fake_imap) -> None:
    fake_imap.existing_labels.add("test-inbox")
    select_label(fake_imap, "test-inbox", readonly=False)
    assert fake_imap.select_readonly is False


def test_select_missing_label_raises_scope_violation(fake_imap) -> None:
    with pytest.raises(ScopeViolation, match="not found"):
        select_label(fake_imap, "does-not-exist")
