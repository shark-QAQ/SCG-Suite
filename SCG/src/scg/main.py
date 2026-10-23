"""
SCG 插件的主程序
用于启动 FastMCP 服务，提供代码安全检查工具。
"""
import logging
from typing import Literal

from fastmcp import FastMCP

from .engine import scan_directory
from .models import ScgScanResult
from .rules.builtin import scan_code_content

# 配置日志记录
# 用于记录插件运行时的事件和错误信息
logging.basicConfig(level=logging.INFO, format='[%(name)s] %(message)s')
logger = logging.getLogger("SCG")

mcp = FastMCP("SmartCodeGuard")

Language = Literal["bash", "sql", "javascript", "python", "typescript", "unknown"]


# 定义工具函数
# 用于验证 SCG 插件是否成功加载
@mcp.tool()
def scg_health_check() -> str:
    """验证 SCG 插件是否成功加载"""
    return "SCG is alive and ready to guard your code."


# 定义工具函数
# 用于对一段代码片段进行静态安全检查
@mcp.tool()
def scg_scan(code: str, language: Language = "unknown") -> ScgScanResult:
    """对一段代码片段进行静态安全检查"""
    issues = scan_code_content(code, language)
    is_safe = len(issues) == 0
    return ScgScanResult(
        safe=is_safe,
        summary="代码安全检查通过" if is_safe else f"发现 {len(issues)} 个潜在安全问题",
        issues=issues
    )


# 定义工具函数
# 用于扫描指定目录下的所有代码文件
@mcp.tool()
def scg_scan_dir(dir_path: str) -> ScgScanResult:
    """扫描指定目录下的所有代码文件"""
    return scan_directory(dir_path)


def main():
    logger.info("[SCG] Smart Code Guard MCP 服务正在启动...")
    mcp.run()


if __name__ == "__main__":
    main()
