# 证据复现指南

README 里的每个数字都能被复现。这份文档给出**命令、预期输出、以及"看到什么算通过"**。

跑完之后把结果填进文末的「最近一次复现记录」，附上日期和环境。

> 原则：**不写"大概"、不写"约"。数字要么能跑出来，要么就不写进 README。**

---

## 0. 环境

| 项 | 要求 |
| --- | --- |
| Node / pnpm | Node 20+，pnpm 9+ |
| Python | 3.11+，`uv` |
| DSH | 有即可（`npx` 缓存也行）；没有就用 `--skip-dsh` |
| OS | Windows / Linux（netns 仅 Linux） |

```bash
pnpm install
```

---

## 1. TypeScript 测试 — 66 passed

```bash
pnpm test
```

**预期**：`66 passed`，分布为 core 19 / events 9 / egress 9 / netns 3 / adapter 26。

**通过判据**：退出码 0，且失败数为 0。数不对说明代码变了，**回头改 README，不要改测试**。

---

## 2. Python Code Gate — 19 passed

```bash
cd SCG && uv run pytest -q
```

**预期**：`19 passed`。

---

## 3. SCG-Bench — 30/30、0 硬误报、p50 ≈ 1.5ms

```bash
pnpm bench
```

**预期**：

- 30 个场景全部有结论：**ask 23 / deny 7**
- **0 硬误报**（良性场景被 deny）
- 4 次良性审批摩擦（良性场景被 ask，可接受）
- 延迟：**p50 ≈ 1.5ms，p95 ≈ 3–5ms**

**通过判据**：

| 指标 | 门槛 |
| --- | --- |
| deny 场景拦截率 | 7/7 |
| 良性硬误报 | 0 |
| p95 | 建议 < 10ms |

> ⚠️ 「硬误报」和「审批摩擦」是两回事。良性动作被 `ask` 会多一次点击，但不会阻断工作流；被 `deny` 才是事故。这两个数必须分开统计，否则基准会骗自己。

---

## 4. headless E2E — 9/9 PASS

```bash
pnpm pack:bundle
pnpm e2e
```

**预期**：

```
PASS  DSH exit code 0
PASS  model issued at least 3 requests
PASS  a command tool was exposed (bash/pwsh)
PASS  read .env decision exists
PASS  read .env was ask
PASS  egress curl decision exists
PASS  egress curl was deny
PASS  session tainted
PASS  file sandbox switched to read-only
E2E passed
```

**说明**：本地起一个 mock Anthropic Messages server，不需要真实模型或 API Key。Windows 上真实工具名是 `pwsh`，mock 会自动识别。

**这条最有说服力**——它证明的不是「单元测试通过」，而是「整条链路在真实 harness 里跑通」。

---

## 5. 真实 DSH 加载

```bash
pnpm dsh:setup
pnpm dsh:verify
```

**预期**：`--dump-config` 能看到 bundle；审计首条为

```json
{"type":"runtime.start","payload":{"plugin":"dsh-scg-guard","mode":"enforce","engine":"cedar","failClosed":true}}
```

**通过判据**：`runtime.start` 出现，且 `failClosed: true`。

---

## 6. 发布包 — ≈46KB

```bash
pnpm pack:bundle
ls -lh dsh-scg-guard/*.tgz
```

**预期**：约 46KB（`du -h` 或资源管理器看均可）。

**通过判据**：单文件可安装，装到 DSH profile 后能真实启动，不依赖 workspace 链接。

---

## 7. 隔离检查

```bash
pnpm check:isolation
```

**预期**：pnpm store 指向 `.cache/pnpm-store`，所有 `node_modules` 在项目内，无越界。

---

## 8. netns 探针（仅 Linux）

```bash
pnpm check:netns
```

**预期**：Linux 且环境允许非特权 user namespace 时，输出 `netns local command: netns-ok` 与 `netns external TCP blocked: true`；其余情况打印跳过原因并以 0 退出。

**说明**：依赖非特权 user namespaces。Ubuntu 23.10+ 起该能力默认受 AppArmor 限制（`kernel.apparmor_restrict_unprivileged_userns`），嵌套容器里也可能被禁止——这时探针会跳过，运行时回退到 egress proxy，而不是拒绝全部命令。

想强制校验（环境不满足即失败）：

```bash
SCG_REQUIRE_NETNS=1 pnpm check:netns
```

---

## 9. 一句命令跑完

```bash
pnpm demo:all
```

依次执行：测试 → 基准 → 演示 → 控制台 → 打包 → DSH 加载 → E2E。

**通过判据**：全程无红色输出，末尾 `E2E passed`。

没有 DSH 环境：

```bash
pnpm demo:all --skip-dsh
```

---

## 最近一次复现记录

> 每次发版前更新这一节。**没有记录的版本号，不要对外说数字。**

| 项 | 结果 | 日期 | 环境 |
| --- | --- | --- | --- |
| TS 测试 | 66 passed | 2026-10 | Windows 11 / Node 20 / pnpm 9 |
| Python 测试 | 19 passed | 2026-10 | uv / Python 3.11 |
| SCG-Bench | 30/30（ask 23 / deny 7），0 硬误报 | 2026-10 | 同上 |
| 延迟 | p50 ≈ 1.5ms / p95 ≈ 3–5ms | 2026-10 | 同上 |
| E2E | 9/9 PASS | 2026-10 | 同上 |
| DSH 加载 | 通过 | 2026-10 | 同上 |
| Bundle | ≈46KB | 2026-10 | 同上 |

> 上表是 **Phase 1 记录的初值**。下次跑完请替换成你自己的实测输出（含机器配置），
> 因为不同机器上的 p95 会明显不同——**写"我机器上多少"比写一个漂亮的数字更可信**。
