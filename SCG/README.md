# SCG — Code Gate / MCP 扫描器（Python）

> 该目录已降级为 SCG Runtime 的 **Code Gate 模块**（早期 POC 保留）。
> 主运行时（Cedar 策略、污染追踪、DSH 适配器、审计回放）见仓库根目录
> [`README.md`](../README.md)。

基于 [FastMCP](https://github.com/jlowin/fastmcp) 的代码安全审查服务，供 MCP 客户端调用。
对代码片段或整个目录做静态规则匹配，返回结构化的问题列表。

## 功能

| Tool | 说明 |
| --- | --- |
| `scg_scan(code, language)` | 扫描一段代码，`language` 可选 `bash` / `sql` / `javascript` / `python` / `typescript` / `unknown` |
| `scg_scan_dir(dir_path)` | 递归扫描目录下的 `.py` / `.js` / `.ts` / `.sql` / `.sh` 文件；自动跳过 `.venv`、`node_modules`、`.git` 等目录 |
| `scg_health_check()` | 健康检查 |

## 内置规则

| 规则 | 级别 | 内容 |
| --- | --- | --- |
| `SCG-001` | high | 硬编码密码 / 密钥 / token（支持 `=`、`:` 赋值，排除 `==` 比较与环境变量占位符） |
| `SCG-002` | high | 危险命令（`rm -rf /` 及其变体、`mkfs`、`dd if=`），仅 shell 类语言 |
| `SCG-003` | medium | SQL 注入（字符串拼接、f-string、`str.format`），参数化查询不会误报 |

## 快速开始

```bash
uv sync
uv run scg-server
```

服务默认通过 stdio 与 MCP 客户端通信。在 MCP 客户端中配置：

```json
{
  "mcpServers": {
    "scg": {
      "command": "uv",
      "args": ["run", "--directory", "<SCG 项目绝对路径>", "scg-server"]
    }
  }
}
```

## 测试

```bash
uv run pytest
```

## 目录结构

```
src/scg/
├── main.py            # FastMCP 入口与 tool 定义
├── engine.py          # 目录扫描引擎
├── models.py          # Pydantic 响应模型
└── rules/builtin.py   # 内置安全规则
```
