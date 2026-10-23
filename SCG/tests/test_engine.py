"""
测试目录扫描引擎
"""
import os

from scg.engine import scan_directory
from scg.models import ScgScanResult


def test_missing_path_is_reported_as_unsafe(tmp_path):
    result = scan_directory(str(tmp_path / "does-not-exist"))
    assert result.safe is False
    assert "不存在" in result.summary


def test_safe_directory_passes(tmp_path):
    (tmp_path / "app.py").write_text('print("hello")\n', encoding="utf-8")
    result = scan_directory(str(tmp_path))
    assert result.safe is True
    assert result.issues == []


def test_scan_directory_skips_dependency_and_cache_dirs(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "app.py").write_text('password = "secret123"\n', encoding="utf-8")

    for skipped in (".venv", "node_modules", "__pycache__", ".git"):
        directory = tmp_path / skipped / "lib"
        directory.mkdir(parents=True)
        (directory / "dep.py").write_text('password = "another"\n', encoding="utf-8")
        (directory / "dep.js").write_text('password = "another"\n', encoding="utf-8")

    result = scan_directory(str(tmp_path))
    assert result.safe is False
    assert len(result.issues) == 1
    assert "app.py" in result.issues[0].message
    assert "dep.py" not in result.issues[0].message


def test_scan_directory_uses_relative_paths(tmp_path):
    nested = tmp_path / "pkg"
    nested.mkdir()
    (nested / "app.py").write_text('password = "secret123"\n', encoding="utf-8")

    result = scan_directory(str(tmp_path))
    assert os.path.join("pkg", "app.py") in result.issues[0].message


def test_scan_single_file(tmp_path):
    file_path = tmp_path / "app.py"
    file_path.write_text('password = "secret123"\n', encoding="utf-8")

    result = scan_directory(str(file_path))
    assert result.safe is False
    assert result.issues[0].rule_id == "SCG-001"


def test_file_extension_selects_language(tmp_path):
    # .py 文件不应触发仅适用于 shell 的危险命令规则
    (tmp_path / "app.py").write_text('cmd = "rm -rf /"\n', encoding="utf-8")
    (tmp_path / "run.sh").write_text('rm -rf /\n', encoding="utf-8")

    result = scan_directory(str(tmp_path))
    assert len(result.issues) == 1
    assert "run.sh" in result.issues[0].message
    assert result.issues[0].rule_id == "SCG-002"


def test_scan_result_defaults_are_independent():
    first = ScgScanResult(safe=True, summary="first")
    second = ScgScanResult(safe=True, summary="second")
    first.issues.append("placeholder")
    assert second.issues == []
