# DSH Desktop 接入（已验证）

## 当前状态

| 项 | 值 |
| --- | --- |
| App | DeepSeek Harness Desktop **0.2.1-rc.2**（官方安装包） |
| 安装目录 | `%LOCALAPPDATA%\Programs\DeepSeek Harness` |
| Desktop profile | `~/.dsh/profiles/desktop` |
| 插件 | `dsh-scg-guard@1.1.0`（约 46KB tarball） |
| 启用方式 | 已加入 `dsh.profile.bundles` |
| 审计文件 | `.scg/audit-desktop.jsonl`（项目内绝对路径） |
| 验证 | `runtime.start`，`engine=cedar`，`mode=enforce` |
| MCP server | Python `SCG/` 通过 `@deepseek-ai/dsh-mcp-client` 接入 |
| MCP 工具 | `mcp__scg__scg_health_check` / `scg_scan` / `scg_scan_dir` |
| Web profile | **已清理**（旧 Web 配置已删除） |

## 从 Web 切到 Desktop

1. **官方下载**（不要用第三方镜像）：
   - <https://www.deepseek.com/download/>
   - Windows 直链：<https://download.deepseek.com/desktop/dsh-latest-windows-x64.exe>
2. 安装（NSIS，按用户安装；静默参数 `/S` 可用）。
3. 启动一次 App，生成 `~/.dsh/profiles/desktop`。
4. 用 **Desktop 内置 CLI** 安装插件（npm CLI 会拒绝 desktop profile）：

   ```powershell
   # 把 <repo> 换成你的仓库路径，<version> 换成 dsh-scg-guard/package.json 的版本
   & "$env:LOCALAPPDATA\Programs\DeepSeek Harness\resources\runtime\cli\bin\dsh.cmd" `
     plugin --profile desktop add `
     "<repo>\dsh-scg-guard\dsh-scg-guard-<version>.tgz"
   ```

   该命令会自动把 `dsh-scg-guard` 加入 `dsh.profile.bundles`。

5. 在 `~/.dsh/profiles/desktop/cordis.patch.yml` 末尾追加审计路径覆盖：

   ```yaml
   - id: scg-guard
     name: "dsh-scg-guard"
     config:
       enabled: true
       mode: enforce
       auditPath: <repo>/.scg/audit-desktop.jsonl
       failClosed: true
       lockdownOnTaint: true
       egressProxy: true
       networkIsolation: proxy
   ```

6. 重启 App，确认：

   ```bash
   cat .scg/audit-desktop.jsonl
   # 首条应为 runtime.start，engine=cedar
   ```

## 接入 Python SCG MCP server

`dsh-scg-guard` 只是 Hook 插件，不会自动注册 Python MCP server。需要在
`~/.dsh/profiles/desktop/cordis.patch.yml` 的主配置区加入 `mcp-scg` 行：

```yaml
- insert:
    - id: mcp-scg
      name: "@deepseek-ai/dsh-mcp-client"
      config:
        serverName: scg
        transport: stdio
        command: "<repo>/SCG/.venv/Scripts/python.exe"
        args: ["-m", "scg.main"]
        cwd: "<repo>/SCG"
        env:
          FASTMCP_SHOW_SERVER_BANNER: "false"
          FASTMCP_CHECK_FOR_UPDATES: "off"
        failOnStartupError: false
```

工具名由 `serverName` 决定：`mcp__scg__<tool>`。

### 四个关键点

1. **必须用 `- insert:`**  
   `cordis.patch.yml` 里的直接 `- id:` 是“覆盖已有行”；新插件必须用 `insert`，
   否则不会加载。
2. **`transport: stdio` 必填**  
   缺省时 client 走错传输路径，报 `Cannot read properties of undefined (reading 'sessionId')`。
3. **FastMCP 环境变量格式**  
   `FASTMCP_CHECK_FOR_UPDATES` 只接受 `stable | prerelease | off`；填 `false`
   会让 Python server 在启动时 pydantic 校验失败。
4. **不要把 DSH 内部包装进 profile**  
   `@deepseek-ai/dsh-mcp-client` 及其 peers 由桌面版运行时（app.asar）提供。
   装进 profile 会遮蔽 base bundle，触发 `dsh-scope`、`cordis`、`dsh-sandbox`、
   `dsh-http-proxy` 等无限依赖级联。保持 profile 只装用户插件（guard/skins/model）。

### 验证

```powershell
Get-CimInstance Win32_Process | Where-Object { $_.Name -eq "python.exe" } |
  Select-Object ProcessId,ParentProcessId,CommandLine
```

应看到：

```
...SCG/.venv/Scripts/python.exe -m scg.main
ParentProcessId = DeepSeek Harness 的 PID
```

然后在桌面版**新开一轮对话**，工具列表应出现 `mcp__scg__*`，调用
`mcp__scg__scg_health_check` 应返回 alive。

> 注意：guard 的审计文件 `.scg/audit-desktop.jsonl` 与 MCP server 是两条线；
> guard 拦截的是 Agent 的工具调用，MCP server 提供的是扫描工具本身。

## 注意事项

- **Desktop profile 由 Electron App 管理**：npm 版 `dsh` 拒绝启动/管理它；必须用 App 自带的
  `resources/runtime/cli/bin/dsh.cmd`。
- **安装位置**：桌面版（约 276MB）和 desktop profile 的插件依赖位于用户目录
  （`%LOCALAPPDATA%`、`~/.dsh`、用户级 pnpm store）。这是显式切换桌面版的结果；
  项目本身在 `SCG-Suite` 内的依赖仍然隔离。
- **Desktop 是实验预览**：官方尚未完成安全审计，且可能有破坏性变更。
- Windows 上网络隔离使用 **egress proxy**；`netns` 仅 Linux 可用。
- `~/.dsh/sessions`、`storages`、`.credentials.yaml` 是跨 surface 的用户数据，
  不在本项目目录内，升级/卸载插件时不会改动它们。
- 项目内 `.dsh-home/profiles/e2e` 是 headless E2E fixture，可随时重建。

## 卸载插件

优先用桌面 App 的插件页禁用/卸载；或用内置 CLI：

```powershell
& "...\dsh.cmd" plugin --profile desktop remove dsh-scg-guard
```

## 安装包缓存

如需重装，从官方页面重新下载：

<https://download.deepseek.com/desktop/dsh-latest-windows-x64.exe>

> `dsh:verify` / `e2e` 只重置各自的 `.scg/audit.jsonl` 及其 `.head` sidecar，
> 不会删除桌面版的 `.scg/audit-desktop.jsonl`。
