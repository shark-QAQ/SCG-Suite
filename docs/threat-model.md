# SCG Runtime 威胁模型（Phase 1）

## 1. 系统边界

```
[模型 / 提示词] → DSH Agent Loop → 工具调用
                                    │
                     SCG Bundle ────┤ pre-execute: Cedar 策略
                                    │ session taint
                                    │ 哈希链审计
                                    ▼
                              DSH Sandbox / 工具执行
                                    │
                                    ▼
                         工作区 / 网络 / 生产系统
```

信任边界：

| 边界 | 说明 |
| --- | --- |
| 模型 ↔ Harness | 模型输出不可信；工具参数必须校验 |
| Harness ↔ SCG | SCG 与 Agent 同进程；策略/审计故障必须 fail-closed |
| SCG ↔ 沙箱 | 策略允许 ≠ 内核放行；最终能力由 sandbox 收口 |
| SCG ↔ 审计 | 本地审计可被同权限攻击者删除；哈希链只能证明"链内"完整性 |

## 2. 资产

- 密钥、连接串、`.env`、SSH key、云凭据
- 源代码与未发布变更
- 生产数据库 / 基础设施
- 审计记录与策略版本
- Agent 会话状态（taint、审批）

## 3. 对手与场景

| 对手 | 能力 | 典型场景 |
| --- | --- | --- |
| 犯错的模型 | 生成危险但非恶意命令 | `rm -rf /`、误删生产表 |
| 提示注入 | 通过仓库内容/网页控制模型 | 读取 `.env` 后外传 |
| 恶意内部人 | 有本机权限 | 篡改审计、绕过插件 |
| 供应链 | 污染依赖/策略包 | 恶意策略放行、插件后门 |
| 好奇的 Agent | 按"调试"理由扩大权限 | 读取凭据、连接外网 |

**不在 Phase 1 范围**：内核提权漏洞、跨进程内存读取、物理攻击、多租户隔离。

## 4. 威胁与缓解

| 威胁 | 缓解 | 当前状态 |
| --- | --- | --- |
| 破坏性命令 | 结构分类 + Cedar `ask-destructive` + 审批 | 已实现 |
| 密钥外泄 | 文件/环境变量识别 → 会话 taint → egress deny | 已实现 |
| 混淆/编码绕过 | 分类器 + DSH 沙箱能力收口 | 部分（L1 可绕过；L2/L2.5 兜底） |
| 未授权写工作区外 | `fs.write` 路径判定 + ask | 已实现 |
| 污染后的文件破坏（含 L1 绕过） | 会话切 `read-only` 文件沙箱（DSH `sandbox/mode`） | 已实现（文件效果） |
| 污染后的 proxy-aware 外联 | 对污染会话注入本地 egress proxy，默认只放行 loopback | 已实现（proxy-aware） |
| raw socket / 非代理外联（Linux） | 可选 `unshare --net` 网络命名空间 | 已实现（opt-in + CI 探针） |
| raw socket（Windows） | 暂无内核级方案 | 缺口（需 Firewall/WFP） |
| 策略引擎故障 | `failClosed=true` 直接 deny | 已实现 |
| 审计被篡改 | SHA-256 哈希链 + 校验 | 已实现（本地完整性；无密钥） |
| 审计被尾部截断 | `.head` sidecar 记录最后 seq/hash | 已实现（同权限可同时删除两者） |
| 审计泄漏密钥 | `redactSecrets` 递归脱敏 | 已实现（best-effort） |
| 批准 A 执行 B | DSH 审批绑定 `callId`；SCG 记录 action fingerprint 并可一次性预授权 | 已实现（交互式批准不复用） |
| 插件/依赖供应链 | 锁定依赖、pnpm store 隔离、后续签名/SBOM | 部分 |
| 策略被恶意修改 | 签名策略包、版本回滚 | Phase 2 |
| 审计被整文件删除 | 远端锚定/OTLP 导出 | Phase 2 |

## 5. 已知限制（必须诚实披露）

1. **分类器是启发式的**：结构规则覆盖常见形态，但不是完整 shell 解析器；
   变量间接、编码管道、解释器逃逸等仍可能漏判。最终保证来自沙箱，而不是
   字符串匹配。完整清单见 [`known-gaps.md`](known-gaps.md)。
2. **Windows 沙箱是 partial**：DSH `sandbox-local` 使用 ACL restricted-token，
   只覆盖部分文件效果；Linux Landlock 才是 full。
3. **没有系统调用级污染追踪**：Phase 1 的 taint 来自工具级观测（文件路径、命令内容），
   不是 eBPF/strace。读取发生在子进程内部时可能不可见。
4. **DSH 沙箱只覆盖文件效果**：`read-only` / `workspace-write` 不限制网络。
   proxy-aware 外联由本地 egress proxy 覆盖；raw socket 仍是缺口。
5. **egress proxy 不是内核级**：只影响遵守 HTTP(S)_PROXY 的客户端；
   直接 socket、非代理协议仍可绕过。代理也不检查 TLS 内容。
   Linux 可通过 opt-in `netns` 覆盖 raw socket；Windows 仍无内核级方案。
6. **沙箱锁定是会话级**：切到 `read-only` 后，后续合法写入也会失败；
   用户可通过 DSH 策略控件显式切回。
7. **交互式审批不跨调用复用**：SCG 通过 `approval/request` 观察 DSH 的
   `callId` 结果并写入 fingerprint 审计，但不会把一次批准变成长期授权。
   headless 预授权必须显式调用 `apply()` 返回的 `approve()`，且一次性消费。
8. **审计脱敏是 best-effort**：无法识别所有密钥格式；审计文件本身应限制权限。
9. **同权限攻击者可删除审计文件**：哈希链能发现链内篡改，`.head` sidecar
   能发现尾部截断，但攻击者可同时删除两者；需要远端锚定。
10. **审计链不是密码学防篡改**：无密钥 SHA-256 允许有写权限者重算整条链。

## 6. 安全目标与度量

| 目标 | 度量 |
| --- | --- |
| 高危命令不静默执行 | 演示语料 100% ask/deny |
| 污染后 egress 不执行 | 污染链测试 100% deny |
| 策略/引擎故障 fail-closed | 故障注入测试 |
| 审计可验证 | 哈希链 100% 校验 |
| 审计无明文密钥 | 脱敏测试 + 基准扫描 |
| 决策开销可接受 | p95 < 20ms |

### 当前基准（SCG-Bench v0.1）

- 攻击拦截：30/30（100%；`ask` + `deny`，其中 `deny` 7、`ask` 23）
- 良性硬误报：0/30（0%）；审批摩擦 4/30
- 决策延迟：p50 约 1.5 ms，p95 约 3-5 ms（目标 <20 ms；首调用含 WASM 预热）
- 已知绕过：5/5（变量间接、编码管道、解释器逃逸）——单列报告。
- L2 兜底：污染后会话切 `read-only` 文件沙箱；文件效果由 OS 层拒绝。
- L2.5 兜底：污染会话的 proxy-aware 外联经过本地 egress proxy，
  默认只允许 loopback；raw socket 仍是缺口。
- 真实 E2E（`pnpm e2e`）：DSH headless + mock Messages API 验证
  `cat .env → ask/taint/read-only → curl → deny` 的完整链路。
- Linux raw socket：`pnpm check:netns` 在 CI 中验证 netns 内本地命令可运行、
  外部 TCP 被阻断；Windows 自动 skip。

## 7. 后续工作

- 把 Cedar 策略字段映射到 DSH sandbox lease（文件/网络 allowlist）。
- 用 `dsh-llm-replay` 构建 30+ 攻击场景的确定性 E2E。
- 引入策略包签名（cosign）与 SBOM。
- 审计远端锚定 / SIEM 导出。
- 在 Linux CI 上验证 Landlock full 模式。
