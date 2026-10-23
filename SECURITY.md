# Security Policy

## Supported versions

| Version | Supported |
| --- | --- |
| 1.1.x | ✅ |
| < 1.1 | ❌ |

## Reporting a vulnerability

请**不要**通过公开 issue 报告可利用的绕过或安全缺陷。

- 私下联系维护者（仓库 owner 的 GitHub 邮箱），或使用 GitHub 的
  **Security → Report a vulnerability**（Private vulnerability reporting）。
- 请包含：受影响版本、复现步骤、期望行为、实际行为，以及影响评估。
- 如果可能，附上一个最小 `known-gaps.json` 场景或测试用例。

我们会在 7 天内确认收到，并在修复可用后协调披露。没有漏洞赏金计划。

## Scope

**属于安全报告的问题：**

- 能绕过**所有**强制层（L1 策略 + L2 文件沙箱 + L2.5/L2.6 网络隔离）
  并造成实际影响的形态；
- 审计链在正常使用下被静默破坏（例如哈希不一致、fail-open）；
- 审批/授权绑定错误，导致批准 A 能执行 B；
- egress proxy 的崩溃、SSRF、DNS rebinding 或越权放行；
- 审计日志泄漏明文密钥；
- 插件在引擎/审计/沙箱故障时 fail-open。

**不属于安全报告（已在 [docs/known-gaps.md](docs/known-gaps.md) 公开）：**

- 分类器无法解析的 shell 形态（变量间接、编码管道、解释器逃逸等）；
- 未监控工具默认放行（可用 `unmonitoredTools: deny` 收紧）；
- 只覆盖 proxy-aware 客户端的 egress 限制；
- Windows 缺少内核级网络隔离；
- 无密钥哈希链可被同权限攻击者重算；
- 交互式审批不跨调用复用。

如果你不确定某个问题是否属于已披露范围，仍然建议私下报告，我们会一起判断。

## Hardening checklist for deployments

- 保持 `failClosed: true`（默认）；
- 严格场景设置 `unmonitoredTools: deny`；
- 用 `egressAllowlist` 明确放行目标，不要使用 `"*"`；
- 审计文件放在只有运行用户可读写的目录，并定期导出到远端；
- Linux 上考虑 `networkIsolation: netns`；
- 不要把 SCG 当成内核沙箱的替代品——它是策略与数据流层，最终能力仍由
  DSH sandbox 和操作系统收口。
