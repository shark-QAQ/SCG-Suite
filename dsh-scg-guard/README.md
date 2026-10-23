# dsh-scg-guard

SCG Runtime 的 DSH 适配器。监听 `tools/pre-execute`，把工具调用归一化为 SCG 动作，
交给 **Cedar WASM** 策略引擎，返回 `allow` / `ask` / `deny`，并写入哈希链审计。

## 决策模型

| 风险 | 示例 | 决策 |
| --- | --- | --- |
| 低 | `npm test`、工作区内读取 | allow |
| 中 | `curl`、读取 `.env`、工作区外写入 | ask（或按审批放行） |
| 高 | `rm -rf /`、`mkfs`、`DROP TABLE` | ask（绑定一次性审批） |
| 严重 | 已污染会话的网络出站 | **deny**（审批不能覆盖） |

`ask` 由 DSH 审批流绑定到具体 `callId`；SCG 同时记录该动作的
`actionFingerprint`，并写入 `approval.granted` / `approval.rejected` 审计。
交互式批准不会变成可复用的长期授权——DSH 已经执行了那一次调用。

需要 headless 预授权时，使用 `apply()` 返回的 `approve(sessionId, action)`：
授权按 fingerprint 精确匹配，并在下一次放行时由 `consumeApproval()` 一次性消费，
因此批准 A 不能执行 B，也不能重复放行 A。

## L2 文件沙箱

检测到 `.env`、SSH key、云凭据等敏感数据被读取后，适配器通过 DSH 官方
`session.append('sandbox/mode', { mode: 'read-only' })` 把该会话的文件沙箱
切到只读。后续 bash/pwsh 调用由 DSH `sandbox-policy` 解析该事件：

- Linux：`bash-sandbox` + Landlock/bubblewrap
- Windows：`pwsh-sandbox` + ACL restricted token（partial）

这层兜底覆盖 L1 分类器漏掉的变量间接、解释器逃逸、编码管道等文件破坏。
**网络不在 DSH 沙箱词汇内**，因此另加 egress proxy。

## Egress proxy

DSH 的 `shellEnv` 只允许 `DSH_*`，SCG 包装 `ctx.shell.resolve`，只对已污染会话
注入 `HTTP_PROXY/HTTPS_PROXY/ALL_PROXY`（含小写）。代理：

- 监听 `127.0.0.1`，默认只允许 loopback；`egressAllowlist` 可配置（支持 `host:port` 精确端口）；
- 对 HTTP 转发、对 HTTPS `CONNECT` 做目的地址门禁；
- 阻断目标写入 `egress.blocked` 审计事件。

限制：只覆盖 proxy-aware 客户端；raw socket 仍会绕过。

Linux 上可把 `networkIsolation` 设为 `netns`：命令被包装为
`unshare --user --map-root-user --net -- bash -c ...`，进入无外网的网络命名空间。
启动时探针不可用会回退到 proxy。Windows 目前仍使用 proxy。

## 配置

`cordis.patch.yml` 的 `config` 支持：

| 键 | 默认 | 说明 |
| --- | --- | --- |
| `enabled` | `true` | 总开关 |
| `mode` | `enforce` | `enforce` 阻断/询问；`audit` 只记录 |
| `blockOnHigh` | — | 兼容旧配置；`false` 等价于 `audit` |
| `policyPath` | 内置策略 | 自定义 Cedar 策略 JSON（policyId → 文本） |
| `auditPath` | `.scg/audit.jsonl` | 审计文件；`null` 表示只存内存 |
| `failClosed` | `true` | 引擎/审计故障时拒绝监控工具 |
| `lockdownOnTaint` | `true` | 会话接触敏感数据后，把 DSH 文件沙箱切到 `read-only` |
| `egressProxy` | `true` | 污染会话注入本地 egress 代理 |
| `egressAllowlist` | loopback | 代理允许的目标；支持 `.example.com` 后缀、`*`、`host:port` 精确端口 |
| `egressProxyUrl` | — | 测试/高级：直接指定代理 URL，不启动内置代理 |
| `networkIsolation` | `proxy` | `off` / `proxy` / `netns`（Linux 可选） |

## 在 DSH 中启用

1. 把 `dsh-scg-guard` 加入 profile 的 `dependencies`。
2. **必须**把它加入 `dsh.profile.bundles`——只加依赖不会启用 bundle。
3. 重启 DSH。

项目内可复现验证：

```bash
pnpm dsh:setup    # 在 .dsh-home 创建测试 profile，不碰 ~/.dsh
pnpm dsh:verify   # 启动 DSH，等待审计日志中的 runtime.start
```

预期：

```
DSH loaded plugin: {"plugin":"dsh-scg-guard","mode":"enforce","engine":"cedar","failClosed":true}
```

## 审计

每次加载写入 `runtime.start`；每次工具决策写入 `decision.made`；
敏感数据接触写入 `session.tainted`；审批结果写入 `approval.granted` /
`approval.rejected`。事件通过 SHA-256 哈希链串联，加载时校验；
字符串字段在落盘前脱敏。

`.head` sidecar 记录最后一条事件的 seq/hash，用于发现尾部截断。轮转或删除
审计文件时必须同时删除 `<audit>.head`；只删 JSONL 会被判定为截断并
fail-closed。

## 真实 DSH E2E

```bash
pnpm pack:bundle
pnpm e2e
```

启动项目内 mock Messages API 与 DSH headless，验证
`cat .env → ask/taint/read-only → curl → deny` 的完整链路。

## 打包与分发

```bash
pnpm pack:bundle
# → dsh-scg-guard/dsh-scg-guard-<version>.tgz（约 46KB）
```

发布包由 esbuild 生成：`@scg/core`、`@scg/events`、`@scg/egress` 全部内联进
`dist/index.js`，策略 JSON 一并打包；只有 `@cedar-policy/cedar-wasm` 保持为
npm 依赖。安装到 DSH profile 时不再需要 workspace 链接。

## 开发

```bash
pnpm --filter @scg/core build
pnpm --filter @scg/events build
pnpm --filter @scg/egress build
pnpm --filter dsh-scg-guard test
```

或从仓库根目录：

```bash
pnpm build
pnpm test
```
