# 开发与隔离规范

本项目以"不污染宿主环境"为前提开发。

## 硬性规则

1. **Python**：只使用 `uv` 在项目目录内创建 `.venv`。依赖写入对应 `pyproject.toml`；禁止全局 `pip install`。
2. **Node**：依赖只安装到项目内 `node_modules`。禁止 `npm install -g`、全局 CLI 安装。
3. **缓存隔离**：pnpm store 指向项目 `.cache/pnpm-store`；Python 使用 `UV_CACHE_DIR=<repo>/.cache/uv`。
4. **Rust / Cedar / Go**：本机未安装，不运行 `rustup`、`cargo install` 或系统包管理器。策略引擎使用项目内 Cedar WASM。
5. **DSH**：优先使用已安装的 DSH Desktop 0.2.1-rc.2 内置 CLI；无桌面版时回退 npx 缓存。集成测试使用项目内 `DSH_HOME`。
6. **Docker/WSL**：只使用已安装实例；不拉取镜像、不安装 WSL 发行版，除非明确批准。

## 常用命令

```bash
# 工作区依赖（仅项目内）
pnpm install

# 隔离自检：store 与所有 node_modules 必须指向仓库内
pnpm check:isolation

# 构建 / 测试 / 演示 / 基准
pnpm build
pnpm test
pnpm demo
pnpm bench

# 一键完整演示（测试 → 基准 → demo → dashboard → bundle → DSH → E2E）
pnpm demo:all
# 无 DSH 环境可跳过 DSH 步骤
pnpm demo:all --skip-dsh

# 生成可分发 tarball（内联 @scg/*，仅 Cedar 为外部依赖）
pnpm pack:bundle

# 真实 DSH headless E2E（本地 mock Messages API，无真实模型）
pnpm e2e

# Linux raw-socket 隔离探针（Windows 自动 skip）
pnpm check:netns

# 实时审计控制台（SSE）
pnpm console

# Python 端（复用已有 uv 环境）
cd SCG
uv sync
uv run pytest
```

## 桌面版

可选安装官方 DSH Desktop，并在 `desktop` profile 中启用插件。
安装、审计路径与卸载方式见 [`desktop.md`](desktop.md)。

> 桌面版属于宿主安装；项目内依赖仍保持隔离。

## 项目内 DSH 测试环境

```bash
pnpm dsh:setup    # 生成 .dsh-home/profiles/web，并把插件加入 dsh.profile.bundles
pnpm dsh:verify   # 启动 DSH，等待 .scg/audit.jsonl 中的 runtime.start
```

- `DSH_HOME` 只指向项目内 `.dsh-home`；脚本会拒绝写入 `~/.dsh`。
- DSH CLI 优先使用桌面版内置命令；也可用 `DSH_BIN` 指定；无桌面版机器才回退 npx 缓存。
- 如果 CI 中找不到 DSH，`dsh:verify` 默认跳过；设置 `SCG_REQUIRE_DSH=1` 可强制失败。

## 目录职责

| 目录 | 职责 |
| --- | --- |
| `packages/scg-core` | 策略类型、风险分类、Cedar WASM 策略引擎 |
| `packages/scg-events` | 哈希链事件日志、JSONL 存储、确定性回放 |
| `dsh-scg-guard` | DSH 适配器（`tools/pre-execute`） |
| `SCG` | Python Code Gate / MCP 扫描器（保留） |
| `docs` | harness 内部机制、威胁模型、ADR |
| `demo` | 失控 Agent 演示脚本 |
