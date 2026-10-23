"""
内置规则
用于扫描代码片段中的硬编码密码、危险命令和 SQL 注入等风险。
"""
import re
from typing import List
from ..models import ScgIssue

# 适用危险命令规则的语言
_SHELL_LANGUAGES = {"bash", "shell", "sh", "zsh", "unknown"}
# 适用 SQL 注入规则的语言
_SQL_LANGUAGES = {"sql", "unknown"}

# 规则 1：硬编码密码/密钥
# 支持 Python/JS 的 `name = "value"` 以及 YAML/JSON 的 `name: "value"`；
# 通过前后断言排除 `==`、`!=`、`>=` 等比较运算，避免误报。
_SECRET_PATTERN = re.compile(
    r"""(?ix)
    \b(?:password|passwd|secret|api[_-]?key|access[_-]?key|token)["']?
    \s*(?:(?<![=!<>])=(?!=)|:)\s*
    (["'])(?!\s*(?:\$\{|%\(|\{\{))([^"'\n]{1,200})\1
    """
)

# 规则 2：危险命令
# rm 的 -r/-f 可以合并、调换顺序，或写作长选项，因此逐个参数判断。
_RM_PATTERN = re.compile(r"\brm\b([^\n;&|]*)", re.IGNORECASE)
_MKFS_PATTERN = re.compile(r"\bmkfs(?:\.[a-z0-9]+)?\b", re.IGNORECASE)
_DD_PATTERN = re.compile(r"\bdd\s+[^\n;&|]*\bif=", re.IGNORECASE)

# 规则 3：SQL 注入
# 覆盖字符串拼接、f-string 插值和 str.format 三种常见形式。
_SQL_INJECTION_PATTERN = re.compile(
    r"""(?ix)
    (?:
        \b(?:select|insert|update|delete)\b[^\n]*?\+\s*[A-Za-z_$'"`(]
      | \bf(["'])[^\n]*?\b(?:select|insert|update|delete)\b[^\n]*\{[^}\n]*\}
      | \b(?:select|insert|update|delete)\b[^\n]*?\bformat\s*\(
    )
    """
)


def _is_dangerous_rm(code: str) -> bool:
    """判断是否包含递归且强制删除绝对路径/根目录的 rm 命令"""
    for match in _RM_PATTERN.finditer(code):
        recursive = False
        force = False
        targets = []

        for token in match.group(1).split():
            if token.startswith("-") and len(token) > 1:
                flags = token.lower()
                recursive = recursive or "r" in flags
                force = force or "f" in flags
                continue
            targets.append(token)

        if recursive and force and any(
            target.startswith("/") or target in ("~", "$HOME")
            for target in targets
        ):
            return True

    return False


def scan_code_content(code: str, language: str = "unknown") -> List[ScgIssue]:
    """核心扫描逻辑，纯函数，不依赖外部状态"""
    issues: List[ScgIssue] = []

    # 规则 1：硬编码密码（与语言无关）
    if _SECRET_PATTERN.search(code):
        issues.append(ScgIssue(
            rule_id="SCG-001", severity="high",
            message="发现疑似硬编码密码或密钥",
            suggestion="请将敏感信息移至环境变量。"
        ))

    # 规则 2：危险命令 (仅限 shell 类语言)
    if language.lower() in _SHELL_LANGUAGES:
        if (
            _is_dangerous_rm(code)
            or _MKFS_PATTERN.search(code)
            or _DD_PATTERN.search(code)
        ):
            issues.append(ScgIssue(
                rule_id="SCG-002", severity="high",
                message="发现极度危险的文件系统破坏命令",
                suggestion="禁止直接执行格式化或递归删除根目录的命令。"
            ))

    # 规则 3：SQL 注入
    if (
        language.lower() in _SQL_LANGUAGES
        or re.search(r"\bselect\b", code, re.IGNORECASE)
    ):
        if _SQL_INJECTION_PATTERN.search(code):
            issues.append(ScgIssue(
                rule_id="SCG-003", severity="medium",
                message="发现潜在的 SQL 注入风险",
                suggestion="请使用参数化查询或 ORM 框架。"
            ))

    return issues
