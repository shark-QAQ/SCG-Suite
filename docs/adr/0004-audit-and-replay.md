# ADR 0004: 哈希链审计与确定性回放

## 状态

已接受（Phase 1）

## 背景

企业安全产品必须回答"当时为什么放行/拦截"，并且策略升级后要能评估影响。

## 决定

- 每个决策写一条 `decision.made` 事件到追加写 JSONL。
- 事件包含：action、会话 taint/approval 快照、决策、策略 ID、风险证据、延迟。
- 每条事件通过 `prevHash + stableStringify(event)` 计算 SHA-256，形成哈希链。
- 加载时校验链；断链/篡改直接拒绝。
- `replayDecisions` 用当前策略重算，逐条对比录制决策，输出漂移。
- 审计字符串递归脱敏（Bearer、key=value、URL 凭据）。

## 后果

- 策略变更的影响可量化（matched / mismatches）。
- 本地审计只能证明链内完整性；整文件删除需要 Phase 2 的远端锚定。
- 脱敏是 best-effort，审计文件仍需文件系统权限保护。
- 回放使用脱敏后的 action；含密钥字面量的命令可能出现回放差异，需在基准中单独标注。
