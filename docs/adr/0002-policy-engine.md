# ADR 0002: 使用 Cedar WASM 作为策略引擎

## 状态

已接受（Phase 1）

## 背景

需要一种企业可理解、可测试、可版本化的策略语言，用来表达：

- 低风险放行
- 中/高风险进入审批
- 污染数据禁止外传
- 破坏性操作需要人工授权

本机没有 Rust 工具链，且要求不安装系统软件。

## 选项

1. **自研 DSL**：可控，但没有生态，容易被看作玩具。
2. **OPA / Rego**：企业认知度高，但需要额外运行时或 WASM 包。
3. **Cedar + WASM**：Rust 原生策略语言，npm 提供 WASM 绑定，可直接在 Node 中运行。

## 决定

选择 **Cedar WASM**（`@cedar-policy/cedar-wasm`，项目内依赖）。

- 策略以 `policyId -> Cedar 文本` 的 JSON 文件维护，ID 决定审计可解释性。
- Cedar 负责 allow/deny；TS 层把 `ask-*` 与 `deny-*` 映射为三级决策。
- 策略在构造时用 `checkParsePolicySet` 校验；解析失败直接 fail-closed。

## 后果

- 不需要 Rust/Cedar CLI，符合隔离约束。
- 策略可单元测试、可版本化、可签名（Phase 2）。
- 未来可以增加 OPA 兼容层，而不改变运行时契约。
- 需要维护 Cedar 策略与 TS 分类器之间的字段契约。
