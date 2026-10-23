# 已知绕过与剩余缺口

这份文档主动列出 SCG **当前无法保证**的边界。安全工具的价值不在于宣称
零绕过，而在于让使用者知道保证从哪里开始、在哪里结束。

> 版本：`dsh-scg-guard@1.1.0`（2026-10）。新增绕过请按
> [SECURITY.md](../SECURITY.md) 报告。

---

## 1. L1 分类器（字符串 / 结构规则）

分类器是启发式的，**不是 shell 解析器**。以下形态在基准中单列，不计入主打分：

| ID | 形态 | 示例 |
| --- | --- | --- |
| G01 | 变量间接 | `X=rm; $X -rf /` |
| G02 | 编码管道 | `printf 'cm0gLXJmIC8=' \| sh` |
| G03 | 解释器逃逸 | `perl -e 'system("rm -rf /")'` |
| G04 | 解释器逃逸 | `python -c "import os; os.system('rm -rf /')"` |
| G05 | 变形编码 | `echo 'ez -es /' \| tr 'a-z' 'n-za-m' \| sh` |

同类未穷举的形态：

- shell 函数、alias、`eval`、命令替换、嵌套引号；
- 把命令写入脚本文件后再执行；
- 通过语言运行时动态拼接命令（`getattr`、反射、模板）；
- Windows 下 `wmic process call create`、计划任务、注册表自启动等；
- 只读取部分敏感字段、或通过数据库/远程 API 取凭据。

**兜底来源**是 L2/L2.5/L2.6，而不是分类器本身。

### 网络判定

- 只识别常见客户端（curl/wget/git/云 CLI/数据库 CLI）和部分解释器 API；
- 自定义二进制、加密隧道、非代理协议不会被 L1 识别；
- `isNetworkCommand` 仍可能漏掉 `subprocess` 包装、动态导入等形态。

### 密钥识别

- 依赖文件名/路径模式（`.env`、`.pgpass`、`id_rsa`、云凭据等）；
- 不认识项目自定义的密钥文件名、数据库连接串、远程 secret manager；
- 解释器读取敏感环境变量（`os.environ` / `process.env` + 敏感键名）已覆盖，
  但通过子进程、配置文件或第三方库间接读取仍可能漏判。

---

## 2. 运行层缺口

### 2.1 未监控工具默认放行

`MONITORED_TOOLS` 之外的工具体会写一条 `tool.unmonitored` 审计事件，但
**默认仍然放行**。这意味着：

- MCP 工具、自定义插件工具、`todo` 等不会经过 L1 策略；
- 如果某个未监控工具内部能执行命令或访问网络，它不享受本项目的保护。

需要严格模式时设置：

```yaml
unmonitoredTools: deny
```

生产环境建议把工具名显式加入监控集合，或保持 `deny`。

### 2.2 Taint 是工具级观测，不是系统调用追踪

- taint 来自“工具调用看起来读了敏感文件/环境”；
- 子进程内部、运行时库、远程服务里的读取不可见；
- 无法跟踪数据在内存中的复制、编码、分片。

### 2.3 `ask` 会保守地触发 taint

为了安全，只要动作进入 `ask` 且未被 deny，SCG 就按“可能已执行”处理：
切只读沙箱、标记 taint。若用户随后拒绝，沙箱不会自动恢复。这是有意的
fail-safe，但会造成额外的写失败；用户可通过 DSH 的沙箱策略控件切回。

### 2.4 Egress proxy 只覆盖 proxy-aware 客户端

- 只有遵守 `HTTP(S)_PROXY` 的客户端会被门禁；
- raw socket、UDP、ICMP、非 HTTP 协议直接绕过；
- 不检查 TLS 内容（没有 MITM）；
- 默认只允许 loopback，放行域名需要显式 `egressAllowlist`；
- allowlist 可用 `host:port` 固定端口；不带端口的规则仍允许该主机的任意端口；
- 允许域名解析到私网/回环地址时会被拒绝（`egressAllowPrivate` 可显式放开），
  这降低了 DNS rebinding/SSRF 风险，但不是完整的网络隔离。

### 2.5 Linux netns 是 opt-in 且有环境依赖

- 仅 Linux；需要 unprivileged user namespaces；
- 嵌套容器/沙箱可能禁止 `unshare`；
- 探针失败时回退 proxy，而不是拒绝全部命令；
- 仅包装 `ctx.shell.resolve` 的 `command`，不覆盖非 shell 工具。

### 2.6 Windows 没有内核级网络隔离

- 只有 egress proxy；
- raw socket 仍可外联；
- DSH 的 Windows 文件沙箱是 partial（ACL restricted token）。

### 2.7 文件沙箱限制

- DSH 沙箱词汇只有文件效果，不覆盖网络；
- 会话切到 `read-only` 后，后续合法写入也会失败；
- 用户可显式切回，SCG 不会阻止用户自己的策略操作。

---

## 3. 审计与审批

### 3.1 哈希链不是密码学防篡改

- 无密钥 SHA-256：有写权限者可以重算整条链；
- `.head` sidecar 能发现尾部截断，但同权限攻击者可以同时删除/改写；
- 轮转日志时必须同时处理 `<audit>.head`。只删 JSONL 会留下 sidecar，
  插件会判定为截断并 fail-closed（这是预期行为，不是 bug）；
- 没有远端锚定，不能证明日志在本地之外仍然完整；
- 脱敏是 best-effort，不能保证所有密钥格式都被识别。

### 3.2 交互式审批不跨调用复用

- DSH 的 `ask` 绑定具体 `callId`；SCG 记录该动作的 fingerprint 到审计；
- 一次交互式批准不会变成长期授权；
- headless 预授权必须显式调用 `apply()` 返回的 `approve()`，且一次性消费；
- 如果 DSH 没有提供 `callId`，SCG 会写 `runtime.error` 说明绑定不可用，
  但 `ask` 本身仍由 DSH 处理。

### 3.3 审计故障时的行为

- `enforce` 模式：策略引擎、审计、沙箱锁定、egress 隔离不可用时，
  被监控动作 fail-closed；
- `audit` 模式：只记录，不阻断；审计故障也不会改变执行；
- 未监控工具不受上述 fail-closed 保护。

---

## 4. 1.1.0 已修复的公开绕过

以下问题在 1.1.0 中修复并有回归测试覆盖，列出来是为了说明哪些形态
**不再**是缺口：

| 形态 | 修复 |
| --- | --- |
| `rd /s /q C:\`、`del /f /s /q C:\Windows` | Windows 批量删除识别 |
| `diskpart`、`Clear-Disk`、`Format-Volume` | 磁盘操作识别 |
| `rm -rf ~/`、`$HOME/`、`${HOME}/` | home 目录删除识别 |
| `python -c "open('.env').read()"` | 去标点后匹配密钥路径，产生 taint |
| `python -c "print(os.environ['AWS_SECRET_ACCESS_KEY'])"` | 解释器环境变量读取识别 |
| `cat production.env`、`.pgpass`、`kubeconfig` | 密钥文件名扩展 |
| `CONNECT host:abc` / 畸形 IPv6 | 端口/authority 校验，返回 400 不崩溃 |
| `undefined` payload 字段 | 哈希前裁剪，JSONL 重载一致 |
| 审计尾部截断 | `.head` sidecar 检测 |

---

## 5. 如何新增已知绕过

如果你找到一个当前未覆盖的形态：

1. 在 `benchmark/corpus/known-gaps.json` 增加场景（或直接提 issue）；
2. 说明它属于 L1、L2、L2.5、L2.6 还是审计层；
3. 如果它能绕过**所有**层并造成实际影响，请按 [SECURITY.md](../SECURITY.md)
   私下报告，而不是先公开。
