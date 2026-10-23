# SCG Console

两个入口，零前端框架、零服务器依赖：

## 1. 静态审计视图（适合截图/归档）

```bash
pnpm dashboard
# → demo/out/dashboard.html
```

读取 `demo/out/audit.jsonl` 与 `demo/out/replay.json`，生成自包含 HTML：

- 哈希链状态
- 决策时间线
- 污染链：`.env → session tainted → blocked egress`
- 确定性回放（当前审批 vs 撤销审批）
- SCG-Bench 摘要

## 2. 实时控制台（适合演示）

```bash
pnpm console
# → http://127.0.0.1:4173
```

- 自动选择最新的审计文件：
  - `.scg/audit.jsonl`（DSH / E2E）
  - `demo/out/audit.jsonl`（离线 demo）
- `GET /api/state`：当前事件、回放、基准
- `GET /api/stream`：SSE 增量推送（边跑 `pnpm e2e` 边看决策流入）
- 前端支持 Allow / Ask / Deny 过滤与全文搜索
- 右侧展示污染链、防御分层、回放和 SCG-Bench

说明：replay 面板只在读取 demo 审计时展示，避免把 demo 的回放结果
错误地套到 DSH 会话上。若没有数据，先运行 `pnpm e2e` 或 `pnpm demo`。
