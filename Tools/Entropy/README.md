> # Entropy (恩戳皮)
>
> ### Burp Suite 流量负熵 (Traffic Negentropy)
>
> > **🧭 设计理念：** 让渗透测试流程更加行云流水，哪怕只为你节省一分钟。
>
> **Entropy** 是一款专为 Burp Suite 打造的流量梳理与资产管理插件。它引入了独立的 **“梳理台 (Workspace)”** 概念，帮助安全研究人员从杂乱的 Proxy 历史中抽离高价值资产。配合 **全键盘工作流**，您可以极速完成资产的标记与清洗，并一键投喂给 Xray/Rad 等被动扫描器，实现“人工筛选 + 自动化扫描”的完美闭环。
>
> ## 📸 插件界面示例
>
> ![1.png](https://github.com/xgbtxy/Negentropy-Collective/blob/main/Tools/Entropy/repo/1.png?raw=true)
>
> ![2.png](https://github.com/xgbtxy/Negentropy-Collective/blob/main/Tools/Entropy/repo/2.png?raw=true)
>
> ![3.png](https://github.com/xgbtxy/Negentropy-Collective/blob/main/Tools/Entropy/repo/3.png?raw=true)
>
> ## ✨ 核心功能 (Core Features)
>
> ### 1. 🎯 梳理台 (The Workspace)
>
> **摒弃噪点，聚焦核心。** 彻底告别 Proxy History 中成千上万图片和静态资源的干扰。
>
> - **资产清洗**: 仅将感兴趣的数据包发送至 Workspace，构建高价值的“低熵”资产库。
> - **MIME 仪表盘**: 底部栏实时统计 JSON、HTML、API 等资产分布，资产结构一目了然。
> - **智能去重**: 一键根据 `Host + Method + URL + Params` 指纹清除重复请求，精简测试目标。
> - **高级搜索**: 支持 Regex 正则表达式（如 `login|admin|upload`）与普通关键字匹配。
>
> ### 2. 🎹 极速键盘流 (Keyboard Flow)
>
> **告别右键菜单，建立肌肉记忆。** 在梳理台选中任意请求即可通过快捷键操作：
>
> | 快捷键    | 功能           | 描述                                                  |
> | --------- | -------------- | ----------------------------------------------------- |
> | **1 - 7** | 🏷️ **快速打标** | `1=[SQL]`, `2=[XSS]`... (支持自定义标签)              |
> | **d**     | 🧹 **清除标记** | 撤销误判，一键清空当前行标签                          |
> | **f**     | 🗑️ **删除行**   | 快速移除无用资产                                      |
> | **q**     | 🔗 **投喂代理** | 发送至被动扫描器 (Xray/Rad 等)                        |
> | **w**     | 🔁 **重放器**   | 发送到 Burp Repeater                                  |
> | **e**     | 💣 **攻击器**   | 发送到 Burp Intruder                                  |
> | **c**     | 📋 **极简复制** | 仅复制 Header 和状态码 (Token 节省模式，适合 AI 分析) |
> | **C**     | 📑 **完整复制** | 复制完整数据包 (Shift+c，自动处理二进制防截断)        |
>
> *(提示：所有快捷键均可在 Config 页面自定义或禁用)*
>
> ### 3. 🔗 被动扫描联动 (Proxy Linkage)
>
> **实现无缝的“指哪打哪”工作流。**
>
> 1. 在 Config 页配置被动扫描器监听地址（如 `127.0.0.1:7777`）。
> 2. 在梳理台选中目标请求，按下 **`q`** 键。
> 3. 流量将在后台静默转发，不干扰当前手动测试流程。
>
> ### 4. 🤖 AI 智能复制 (Smart Copy)
>
> 专为投喂 ChatGPT、Claude、DeepSeek 等 AI 模型设计。
>
> - **Copy Lite (`c`)**: 智能丢弃响应体，只保留 Header。极大节省 Token，让 AI 专注于逻辑分析。
> - **Copy Full (`Shift+c`)**: 保留完整文本，自动检测并占位二进制数据（如图片、压缩包）和空字节，有效防止剪贴板截断问题。
>
> ## 🚀 快速开始 (Quick Start)
>
> 1. **下载**: 从 Releases 页面获取最新版本的 `Entropy.jar`。
> 2. **安装**: 在 Burp Suite -> Extensions -> Add 中选择插件文件。
> 3. **使用**: 在 Proxy 历史记录中右键 -> **Send to Workspace**，即可开始体验极速工作流。
>
> ## ⚙️ 配置说明 (Configuration)
>
> - **⌨️ 自定义快捷键**: 不习惯 QWER 布局？您可以自由更改为喜欢的键位。
> - **🌐 代理设置**: 完整支持 HTTP 和 SOCKS5 代理协议。
> - **🧩 自动提取**: 可选开启 URL 和 JSON 参数的自动解析功能。
>
> ## ⚠️ 安全声明
>
> > 本工具仅面向合法授权的企业安全建设、渗透测试及红队演练。请使用者务必遵守当地网络安全法律法规。严禁利用本工具从事任何非法的攻击行为。
>
> <a name="entropy-english"></a>
>
> # Entropy (English)
>
> **Traffic Negentropy for Burp Suite.**
>
> > **Philosophy:** To streamline your penetration testing workflow, saving even just one minute matters.
>
> Entropy is a Burp Suite extension designed to optimize traffic organization. It introduces an independent **Workspace** to extract valuable assets from the chaotic Proxy history. With the **Keyboard Flow**, you can quickly tag, clean, and feed assets to passive scanners (like Xray/Rad) with a single keystroke.
>
> ## ✨ Features
>
> ### 1. 🎯 The Workspace
>
> Filter out the noise. No more distractions from thousands of images and JS files in Proxy History.
>
> - **Asset Cleaning:** Send interesting packets to the Workspace to build your "Low Entropy" asset library.
> - **MIME Dashboard:** Real-time statistics for JSON, HTML, API, etc., displayed on the bottom bar.
> - **Smart Deduplication:** One-click deduplication based on `Host + Method + URL + Params` fingerprint.
> - **Advanced Search:** Supports both Regex and standard keyword matching.
>
> ### 2. 🎹 Keyboard Flow
>
> Say goodbye to context menus.
>
> | Key       | Action         | Description                      |
> | --------- | -------------- | -------------------------------- |
> | **1 - 7** | **Tagging**    | Quick tags like `[SQL]`, `[XSS]` |
> | **d**     | **Clear**      | Clear current tags               |
> | **f**     | **Delete**     | Remove row                       |
> | **q**     | **Feed Proxy** | Send to passive scanner          |
> | **w**     | **Repeater**   | Send to Repeater                 |
> | **e**     | **Intruder**   | Send to Intruder                 |
> | **c**     | **Copy Lite**  | Headers only (Save tokens)       |
> | **C**     | **Copy Full**  | Full text (Binary safe, Shift+c) |
>
> ### 3. 🔗 Proxy Linkage
>
> "Manual Filtering + Automated Scanning" loop.
>
> 1. Configure the scanner address in the Config tab.
> 2. Select requests and press **`q`**.
> 3. Traffic is forwarded silently in the background.
>
> ### 4. 🤖 Smart Copy for AI
>
> - **Copy Lite (`c`)**: Drops response body to save tokens.
> - **Copy Full (`Shift+c`)**: Keeps text but auto-masks binary data to prevent clipboard truncation.
>
> ## 🚀 Installation
>
> 1. **Download:** Get the latest `Entropy.jar` from Releases.
> 2. **Install:** Open Burp Suite -> Extensions -> Add -> Select `Entropy.jar`.
>
> ## ⚙️ Configuration
>
> - **Customize Shortcuts:** Change keys or disable them.
> - **Proxy Settings:** HTTP / SOCKS5 supported.
> - **Auto Extract:** Toggle parameter parsing.
>
> ## ⚠️ Security Disclaimer
>
> This tool is intended for legally authorized use only. Do not use it for illegal purposes.
