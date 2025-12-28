> # Entropy (恩戳皮)
>
> ### Burp Suite 流量负熵 (Traffic Negentropy)
>
> > **🧭 设计理念：** 只为了让你的渗透测试流程，哪怕减少 1分钟。
>
> **Entropy** 是一款专为 Burp Suite 打造的流量梳理与资产管理插件。它引入了独立的 “梳理台 (Workspace)” 概念，让你能从杂乱无章的 Proxy 历史中抽离出高价值资产，通过 **全键盘工作流** 进行极速标记、清洗，并实现一键投喂给 Xray/Rad 等被动扫描器。
>
> [👇 English Version Below / 向下滚动查看英文版](<a name="entropy-english"></a>)
>
> ------
>
> ## 📸 界面预览 (Screenshots)
>
> *(注：如果图片无法加载，请检查网络是否能访问 GitHub 资源)*
>
> ------
>
> ## ✨ 核心功能 (Core Features)
>
> ### 1. 🎯 梳理台 (The Workspace)
>
> **拒绝噪点，只留精华。** 不再被 Proxy History 中成千上万的图片和 JS 干扰。
>
> - **🧹 资产清洗:** 将感兴趣的数据包发送到 Workspace，建立你的“低熵”资产库。
> - **📊 MIME 仪表盘:** 底部实时统计 JSON, HTML, API 等各类资产数量，一目了然。
> - **🧬 智能去重:** 点击按钮，自动根据 `Host + Method + URL + Params` 指纹清除重复请求。
> - **🔍 高级搜索:**
>   - **Regex:** 支持正则表达式（如 `login|admin|upload`）。
>   - **Keyword:** 支持普通关键字匹配（不区分大小写）。
>
> ### 2. 🎹 极速键盘流 (Keyboard Flow)
>
> **告别右键，建立肌肉记忆。** 在梳理台选中行即可操作：
>
> | **快捷键** | **功能**       | **描述**                                   |
> | ---------- | -------------- | ------------------------------------------ |
> | **1 - 7**  | 🏷️ **快速打标** | `1=[SQL]`, `2=[XSS]`... (支持自定义)       |
> | **d**      | 🧹 **清除标记** | 误判撤销，一键清空标签                     |
> | **f**      | 🗑️ **删除行**   | 快速移除无用资产                           |
> | **q**      | 🔗 **投喂代理** | 发送给 Xray/Rad 等被动扫描器               |
> | **w**      | 🔁 **重放器**   | 发送到 Burp Repeater                       |
> | **e**      | 💣 **攻击器**   | 发送到 Burp Intruder                       |
> | **c**      | 📋 **极简复制** | 仅复制 Header 和状态码 (适合 AI 分析)      |
> | **C**      | 📑 **完整复制** | 复制完整包 (自动处理二进制防截断，Shift+c) |
>
> *(注：所有快捷键均可在 Config 页面自定义或禁用)*
>
> ### 3. 🔗 被动扫描联动 (Proxy Linkage)
>
> **人工筛选 + 自动化扫描 = 完美闭环。**
>
> 1. 在 Config 页配置被动扫描器地址（如 `127.0.0.1:7777`）。
> 2. 在梳理台选中请求，按 **`q`** 键。
> 3. 流量在后台静默转发，不干扰当前操作，实现“指哪打哪”。
>
> ### 4. 🤖 AI 智能复制 (Smart Copy)
>
> 专为投喂 ChatGPT/Claude/DeepSeek 设计。
>
> - **Copy Lite (`c`):** 丢弃响应体，只保留 Header。极大节省 Token，让 AI 专注于逻辑分析。
> - **Copy Full (`Shift+c`):** 保留文本，但自动检测并占位二进制数据（图片/压缩包）和空字节，防止剪贴板截断 bug。
>
> ------
>
> ## 🚀 快速开始 (Quick Start)
>
> 1. **下载:** 获取最新版本的 `Entropy.jar`。
> 2. **安装:** Burp Suite -> Extensions -> Add -> 选择 `Entropy.jar`。
> 3. **使用:**
>    - Proxy 右键 -> **Send to Workspace**。
>    - 进入 Entropy 标签页，开始你的键盘流操作。
>
> ## ⚙️ 配置说明 (Configuration)
>
> 在 Config 标签页中，你可以：
>
> - **⌨️ 自定义快捷键:** 不习惯 QWER？改为你喜欢的键位。
> - **🌐 代理设置:** 支持 HTTP 和 SOCKS5 代理。
> - **🧩 自动提取:** 开关是否自动解析 URL 和 JSON 参数。
>
> ## ⚠️ 安全声明
>
> > 本工具仅面向合法授权的企业安全建设、渗透测试及红队演练。请使用者务必遵守当地网络安全法律法规。严禁利用本工具从事任何非法的攻击行为。
>
> ------
>
> <a name="entropy-english"></a>
>
> # Entropy (English)
>
> **Traffic Negentropy for Burp Suite.**
>
> > **Philosophy:** To save just 1 minute in your penetration testing workflow.
>
> Entropy is a Burp Suite extension designed to optimize traffic organization. It provides an independent **Workspace** to extract valuable assets from the chaotic Proxy history, clean them via **keyboard shortcuts**, and feed them to passive scanners (like Xray/Rad) with one click.
>
> ## ✨ Features
>
> ### 1. 🎯 The Workspace
>
> No more noise from thousands of images and JS files in Proxy History.
>
> - **Assets Cleaning:** Send interesting packets to Workspace to build your "Low Entropy" asset library.
> - **MIME Dashboard:** Real-time statistics for JSON, HTML, API, etc. at the bottom bar.
> - **Smart Deduplication:** Click Deduplicate to remove duplicates based on fingerprint.
> - **Advanced Search:** Regex & Keyword support.
>
> ### 2. 🎹 Keyboard Flow
>
> Say goodbye to context menus.
>
> | **Key**   | **Action**     | **Description**                  |
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
> 1. Configure scanner address in Config tab.
> 2. Select requests, press **`q`**.
> 3. Traffic is forwarded silently in the background.
>
> ### 4. 🤖 Smart Copy for AI
>
> - **Copy Lite (`c`):** Drops response body. Saves tokens.
> - **Copy Full (`Shift+c`):** Keeps text, auto-masks binary data to prevent clipboard truncation.
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
