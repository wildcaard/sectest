"""Tests for agent scanner tool registry (tools.py)."""

import pytest

from security_agent.agent.tools import (
    SCANNER_CLASSES,
    get_scanner_tool_definitions,
    get_scanner_class_by_id,
)


def test_scanner_classes_non_empty():
    assert len(SCANNER_CLASSES) >= 1
    for cls in SCANNER_CLASSES:
        assert hasattr(cls, "name")
        assert cls.__module__.split(".")[-1]  # tool_id from module


def test_get_scanner_tool_definitions_returns_enabled_only(config_all_scanners_enabled, config_one_scanner_disabled):
    defs_all = get_scanner_tool_definitions(config_all_scanners_enabled)
    defs_one_off = get_scanner_tool_definitions(config_one_scanner_disabled)
    assert len(defs_all) == len(SCANNER_CLASSES)
    assert len(defs_one_off) == len(SCANNER_CLASSES) - 1
    tool_ids_all = {d["tool_id"] for d in defs_all}
    assert "headers" in tool_ids_all
    tool_ids_one_off = {d["tool_id"] for d in defs_one_off}
    assert "headers" not in tool_ids_one_off
    assert "ssl_tls" in tool_ids_one_off


def test_get_scanner_tool_definitions_structure(config_all_scanners_enabled):
    defs = get_scanner_tool_definitions(config_all_scanners_enabled)
    for d in defs:
        assert "tool_id" in d
        assert "name" in d
        assert "description" in d
        assert isinstance(d["tool_id"], str)
        assert isinstance(d["name"], str)
        assert isinstance(d["description"], str)


def test_get_scanner_tool_definitions_headers_present(config_all_scanners_enabled):
    defs = get_scanner_tool_definitions(config_all_scanners_enabled)
    headers_def = next((d for d in defs if d["tool_id"] == "headers"), None)
    assert headers_def is not None
    assert "HTTP" in headers_def["name"] or "header" in headers_def["name"].lower()


def test_get_scanner_class_by_id_valid():
    cls = get_scanner_class_by_id("headers")
    assert cls is not None
    assert cls.__name__ == "HeadersScanner"
    assert get_scanner_class_by_id("ssl_tls") is not None
    assert get_scanner_class_by_id("cors") is not None


def test_get_scanner_class_by_id_invalid():
    assert get_scanner_class_by_id("nonexistent") is None
    assert get_scanner_class_by_id("") is None


def test_tool_id_matches_config_key(config_all_scanners_enabled):
    defs = get_scanner_tool_definitions(config_all_scanners_enabled)
    config_scanners = config_all_scanners_enabled.get("scanners", {})
    for d in defs:
        assert d["tool_id"] in config_scanners, f"tool_id {d['tool_id']} should exist in config.scanners"
