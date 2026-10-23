"""
SCG 插件的扫描引擎
用于扫描目录中的代码文件，检测其中是否存在安全风险。
"""

import os
from typing import Iterator, List, Tuple

from .models import ScgIssue, ScgScanResult
from .rules.builtin import scan_code_content

# 需要扫描的文件扩展名及其对应的语言标识
_LANGUAGE_BY_EXT = {
    ".py": "python",
    ".js": "javascript",
    ".ts": "typescript",
    ".sql": "sql",
    ".sh": "bash",
    ".bash": "bash",
}

# 扫描时跳过的目录：依赖、缓存和构建产物不属于项目源码
_SKIPPED_DIRS = {
    ".git", ".hg", ".svn",
    ".venv", "venv", "env",
    "node_modules", "__pycache__",
    ".pytest_cache", ".mypy_cache", ".ruff_cache", ".tox",
    "dist", "build", "target",
}


def _iter_source_files(dir_path: str) -> Iterator[Tuple[str, str]]:
    """遍历目录下需要扫描的源码文件，产出 (文件路径, 语言)"""
    for root, dirs, files in os.walk(dir_path):
        # 原地修改 dirs 以阻止 os.walk 进入无关目录
        dirs[:] = sorted(d for d in dirs if d not in _SKIPPED_DIRS)
        for file_name in sorted(files):
            ext = os.path.splitext(file_name)[1].lower()
            language = _LANGUAGE_BY_EXT.get(ext)
            if language is not None:
                yield os.path.join(root, file_name), language


def _scan_file(file_path: str, language: str, display_name: str) -> List[ScgIssue]:
    """扫描单个文件，返回带文件名的问题列表"""
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            code = f.read()
    except (OSError, UnicodeDecodeError):
        # 无法读取的文件（权限、编码等）直接跳过，不影响其余文件的扫描
        return []

    issues = scan_code_content(code, language)
    for issue in issues:
        issue.message = f"文件 {display_name}: {issue.message}"
    return issues


def scan_directory(dir_path: str) -> ScgScanResult:
    if not os.path.exists(dir_path):
        return ScgScanResult(safe=False, summary=f"路径不存在: {dir_path}", issues=[])

    # 允许直接传入单个文件
    if os.path.isfile(dir_path):
        language = _LANGUAGE_BY_EXT.get(os.path.splitext(dir_path)[1].lower(), "unknown")
        issues = _scan_file(dir_path, language, os.path.basename(dir_path))
    else:
        issues = []
        for file_path, language in _iter_source_files(dir_path):
            display_name = os.path.relpath(file_path, dir_path)
            issues.extend(_scan_file(file_path, language, display_name))

    is_safe = len(issues) == 0
    return ScgScanResult(
        safe=is_safe,
        summary="目录扫描通过" if is_safe else f"扫描完成，共发现 {len(issues)} 个问题",
        issues=issues
    )
