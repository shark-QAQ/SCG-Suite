# ADR 0003: 分层强制执行，复用 DSH 沙箱

## 状态

已接受（Phase 1）

## 背景

只用正则匹配命令字符串可以被 base64、变量拼接、`python -c` 等绕过。
真正的保证必须来自执行层。

本机没有 Rust 工具链，但 DSH 自带 `ctx.sandbox` seam 与 `dsh-sandbox-local`：

- Linux：bubblewrap / landlock（full/partial）
- macOS：Seatbelt（full）
- Windows：ACL restricted-token（partial）
- 无可用后端时 fail-closed

## 决定

采用三层：

1. **L1 工具策略**：`tools/pre-execute` + Cedar → allow / ask / deny。
2. **L2 OS 沙箱**：base bundle 默认 `workspace-write`；SCG 检测到敏感数据接触后，
   通过官方 `sandbox/mode` 事件把会话切到 `read-only`。不自研 Landlock，
   直接复用 DSH `sandbox-local`（Linux Landlock/bwrap、Windows ACL）。
3. **L2.5 网络代理**：包装 `ctx.shell.resolve`，对污染会话注入本地 egress proxy；
   默认只放行 loopback，阻断事件写审计。只覆盖 proxy-aware 客户端。
4. **L2.6 Linux netns（可选）**：`networkIsolation: netns` 时把命令包装进
   `unshare --user --map-root-user --net`；探针失败回退 proxy。
5. **L3 数据流**：工具级 taint（文件读取、敏感环境变量）→ 阻断 egress。

Phase 1 不实现 eBPF/strace；在威胁模型中明确标注为限制。
**DSH 沙箱只覆盖文件效果，不覆盖网络**；egress 仍由 L1 + taint 负责。

## 后果

- 可跨平台运行，Windows 也能得到部分强制。
- 策略与沙箱职责清晰：Cedar 解释"为什么"，沙箱保证"做不到"。
- 文件效果已有 L2 兜底；proxy-aware egress 已有 L2.5 兜底。
- Linux raw socket 已有可选 L2.6 netns；Windows 仍需 Firewall/WFP。
- 沙箱锁定是会话级，可能影响后续合法写入；用户可显式切回。
- Linux full 模式的基准需要在 CI/Linux 环境验证。
