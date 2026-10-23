# 60 秒演示 GIF · 分镜与录制脚本

> **当前状态**：`docs/assets/demo.gif` 已用真实 `pnpm demo` 输出渲染生成
> （1080×712，28 帧，约 41 KB，逐行出现 + 末尾定格）。
> 它不是录屏，而是把那次运行的真实逐行输出渲染成动画，内容与终端一致。
>
> 下面这套分镜留给**需要真实录屏**的场合（对外演讲、带真实时序的演示）。
> 日常 README 用现有 GIF 即可。

目标：**让一个没听过这个项目的人在 60 秒内看懂「威胁 → 拦截 → 证据」。**

一句话原则：**GIF 里不要出现"我在操作"，只出现"系统在反应"。** 观众要看的是决策流，不是你的手速。

产出：`docs/assets/demo.gif`，控制在 **8MB 以内**（GitHub 超过 10MB 不渲染）。

---

## 一、录制前准备（10 分钟，一次性）

1. **终端**：Windows Terminal，深色主题，字号 16，窗口固定 **1280×720**
2. **提示符**：临时改成短提示符，别让 `PS D:\Large_Model\VScode_Project\Part3\01-resume\SCG-Suite>` 占半屏

   ```powershell
   function prompt { "scg> " }
   ```

3. **清屏**：`cls`，光标停在左上角
4. **预热**：把所有命令**先跑一遍**，确保输出已经缓存、没有首次安装的等待
5. **脱敏**：确认画面上没有真实 API Key、内网 IP、用户名、公司路径
6. **工具**：[ScreenToGif](https://www.screentogif.com/)（Windows 免安装）或 OBS

> 💡 关键技巧：**不要现场手打命令。** 用 ↑ 调出历史命令，只录"回车"那一下。GIF 会短一半，观感也好得多。

---

## 二、分镜表（总 60 秒）

### 镜头 1｜0:00–0:04　威胁卡（静态图，不用录）

黑底白字，一行：

> **它没有执行任何一条"看起来像攻击"的命令。**

> 配音/字幕：Agent 读了 `.env`，然后把它 `curl` 了出去。

制作：任意图片工具做 1280×720 黑底，截图后作为片头插入。

---

### 镜头 2｜0:04–0:24　核心决策流（20 秒，最重要）

```bash
pnpm demo
```

**录什么**：从回车到四条决策全部打印完。**不要录 npm install、不要录编译。**

画面上应该依次出现：

| 顺序 | 决策 | 字幕（叠加这几个词） |
| --- | --- | --- |
| 1 | `cat .env` → **ASK** | 「读凭据 = 要人点头」 |
| 2 | 批准后 → session **tainted** | 「放行一次 ≠ 放行全部」 |
| 3 | `curl` → **DENY** | 「污染后，外联全断」 |
| 4 | `DROP TABLE` → **DENY** | 「破坏性动作，与污染无关也拦」 |
| 5 | replay **4/4** → 撤销后 **2/4** | 「决策可重放，漂移会暴露」 |

> 🎯 这一镜承担 70% 的说服力。如果只能保留一个镜头，留这个。

---

### 镜头 3｜0:24–0:38　审计控制台（14 秒）

```bash
pnpm dashboard
# 用默认浏览器打开 demo/out/dashboard.html
```

**录什么**：页面加载后，**缓慢滚动一次**，让三块同时出现——哈希链 `VALID` / 决策时间线 / 污染链 `.env → tainted → blocked egress`。

**字幕**：「哈希链 VALID · 污染链可视化 · 确定性回放」

> 用鼠标滚轮慢滚，别用 PageDown（跳帧会让 GIF 花屏）。

---

### 镜头 4｜0:38–0:48　对抗基准（10 秒）

```bash
pnpm bench
```

**录什么**：只录最后 10 行左右的汇总。

**字幕**：「30/30 · 0 硬误报 · p50 1.5ms」

> 如果 bench 输出很长，录之前先 `pnpm bench | Select-Object -Last 15`。

---

### 镜头 5｜0:48–0:58　真实 E2E（10 秒）

```bash
pnpm e2e
```

**录什么**：9 条 `PASS` 逐条滚出，最后 `E2E passed`。

**字幕**：「真实 DSH headless loop，不是 mock 静态图」

---

### 镜头 6｜0:58–1:00　收尾卡（静态图）

> **SCG Runtime** — 会话级 Agent 安全护栏
> `github.com/<你的账号>/scg-suite`

---

## 三、剪辑与压缩

**ScreenToGif 流程：**

1. 录制 12 fps（终端内容不需要 30 fps）
2. 编辑器里删掉首尾空白帧、删掉等待帧
3. 用「减少帧数」把重复的静态帧合并（终端输出停顿处全是重复帧）
4. 导出 GIF，勾选「优化」，目标 **< 8MB**

**目标参数：**

| 参数 | 值 |
| --- | --- |
| 分辨率 | 1280×720 |
| 帧率 | 10–12 fps |
| 颜色 | 256 色够用 |
| 体积 | < 8MB |
| 总时长 | 55–60s |

> 超过 8MB 就砍镜头 4（bench），保留 2/3/5。**宁可少一个镜头，也不要卡顿的 GIF。**

---

## 四、替代方案：用 vhs 生成（可复现）

如果你有 Linux/macOS 或 CI 环境，[vhs](https://github.com/charmbracelet/vhs) 可以把终端录制写成脚本，改一次重跑一次，永远一致。

```tape
# demo.tape
Output docs/assets/demo.gif
Set Shell "bash"
Set Width 1280
Set Height 720
Set FontSize 16
Set Padding 24
Set TypingSpeed 60ms
Set PlaybackSpeed 1.2

Type "pnpm demo"
Enter
Sleep 12s

Type "pnpm bench | tail -12"
Enter
Sleep 8s

Type "pnpm e2e"
Enter
Sleep 15s
```

```bash
vhs demo.tape
```

Windows 上 vhs 支持不佳，**建议用 ScreenToGif**；vhs 留给以后接 CI 自动出图。

---

## 五、录完检查清单

- [ ] 前 4 秒能看懂"威胁是什么"
- [ ] 没有出现真实密钥、内网 IP、公司名、个人用户名
- [ ] 没有 `npm install` 等待画面
- [ ] 没有手打命令的过程
- [ ] 体积 < 8MB，首帧不是黑屏
- [ ] 已在 GitHub 页面上实际渲染验证过（**不要只在本地预览**）

---

## 六、嵌入 README

录完后，把 `docs/assets/demo.gif` 放好，然后取消 README 顶部注释：

```markdown
<!-- TODO(GIF): 录完放到 docs/assets/demo.gif，然后取消下一行注释 -->
<!-- ![demo](docs/assets/demo.gif) -->
```

改成：

```markdown
![SCG Runtime 演示](docs/assets/demo.gif)
```

同时把 README 顶部那句「📹 演示 GIF：录制分镜见…」替换掉——**GIF 到位后，那句话就该消失**。
