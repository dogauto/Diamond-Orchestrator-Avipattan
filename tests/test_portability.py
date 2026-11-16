"""Regression test for Python portability anti-patterns.

Ensures no __import__ anti-patterns, proper forward reference handling,
and correct os.environ usage in diamond/ codebase.
"""

import ast
import sys
from pathlib import Path

import pytest


def _collect_python_files() -> list[Path]:
    """Collect all Python files in src/diamond and tests/."""
    base = Path(__file__).parent.parent / "src" / "diamond"
    files = list(base.rglob("*.py"))
    files.extend((Path(__file__).parent).rglob("test_*.py"))
    # Exclude this test file from self-check to avoid false positives
    return [f for f in files if f.name != "test_portability.py"]


def _check_import_anti_patterns(file_path: Path) -> list[str]:
    """Check a file for __import__ anti-patterns."""
    with open(file_path, "r", encoding="utf-8") as f:
        content = f.read()

    try:
        tree = ast.parse(content)
    except SyntaxError as e:
        return [f"syntax error: {e}"]

    issues = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            if node.func.id == "__import__":
                issues.append(f"line {node.lineno}: __import__ call found")

    return issues


def _check_future_import(file_path: Path) -> list[str]:
    """Check that files with forward references have from __future__ import annotations."""
    with open(file_path, "r", encoding="utf-8") as f:
        content = f.read()

    try:
        tree = ast.parse(content)
    except SyntaxError as e:
        return [f"syntax error: {e}"]

    # Check for forward references (Type hints with quotes)
    has_forward_refs = any(
        isinstance(node, ast.Subscript)
        and isinstance(node.slice, ast.Constant)
        and isinstance(node.slice.value, str)
        and node.slice.value.startswith('"')
        and node.slice.value.endswith('"')
        for node in ast.walk(tree)
        if isinstance(node, ast.Subscript)
    )

    if has_forward_refs:
        # Check for from __future__ import annotations
        has_future_import = any(
            isinstance(node, ast.ImportFrom)
            and node.module == "__future__"
            and any(alias.name == "annotations" for alias in node.names)
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom)
        )

        if not has_future_import:
            return ["missing 'from __future__ import annotations' for forward references"]

    return []


def _check_os_environ_usage(file_path: Path) -> list[str]:
    """Check that os.environ is used, not __import__('os').environ."""
    with open(file_path, "r", encoding="utf-8") as f:
        content = f.read()

    try:
        tree = ast.parse(content)
    except SyntaxError as e:
        return [f"syntax error: {e}"]

    issues = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "__import__":
            # Check if it's importing 'os' and accessing environ
            if len(node.args) >= 1 and isinstance(node.args[0], ast.Constant) and node.args[0].value == "os":
                # Check if the call is used to access 'environ'
                # This is a simplistic check - AST doesn't have parent links by default
                # We'll rely on the __import__ check above for now
                pass

    # Simple text check for the specific anti-pattern
    # Exclude this test file itself from the check
    if "__import__('os').environ" in content and "test_portability.py" not in str(file_path):
        issues.append("__import__('os').environ usage found")

    return issues


@pytest.mark.parametrize("file_path", _collect_python_files())
def test_no_import_anti_patterns(file_path):
    """Test that no __import__ anti-patterns exist in any Python file."""
    issues = _check_import_anti_patterns(file_path)
    assert not issues, f"{file_path}: {issues}"


@pytest.mark.parametrize("file_path", _collect_python_files())
def test_forward_reference_future_import(file_path):
    """Test that files with forward references have __future__ import."""
    issues = _check_future_import(file_path)
    assert not issues, f"{file_path}: {issues}"


@pytest.mark.parametrize("file_path", _collect_python_files())
def test_no_os_import_anti_pattern(file_path):
    """Test that os.environ is used, not __import__('os').environ."""
    issues = _check_os_environ_usage(file_path)
    assert not issues, f"{file_path}: {issues}"


def test_os_environ_used_in_shell_commands():
    """Specific test for shell_commands.py fix."""
    file_path = Path(__file__).parent.parent / "src" / "diamond" / "shell_commands.py"
    with open(file_path, "r", encoding="utf-8") as f:
        content = f.read()

    # Should NOT have the anti-pattern
    assert "__import__('os').environ" not in content
    # Should have the correct usage
    assert "os.environ" in content


def test_json_loads_used_in_provider_metadata():
    """Specific test for provider_metadata.py fix."""
    file_path = Path(__file__).parent.parent / "src" / "diamond" / "provider_metadata.py"
    with open(file_path, "r", encoding="utf-8") as f:
        content = f.read()

    # Should NOT have the anti-pattern
    assert '__import__("json")' not in content
    # Should have the correct usage
    assert "json.loads" in content