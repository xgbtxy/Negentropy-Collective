# Entropy
**Burp Suite Workflow Enhancement Tool / Burp Suite 工作流增强工具**

[![Release](https://img.shields.io/github/v/release/xgbtxy/Negentropy-Collective?include_prereleases&style=flat-square)](https://github.com/xgbtxy/Negentropy-Collective/releases)
[![Author](https://img.shields.io/badge/Author-xgbtxy-blue?style=flat-square)](https://github.com/xgbtxy)

**Entropy** is a Burp Suite extension designed to streamline traffic analysis and automate workflows between Burp and other scanners (like Xray). It bridges the gap between manual analysis and automated scanning.

**Entropy** 是一款 Burp Suite 扩展插件，旨在优化流量分析流程，并打通 Burp 与其他扫描器（如 Xray）之间的自动化工作流。它有效连接了人工分析与自动化扫描的断层。

---

## 🚀 Key Features / 核心功能

### 1. Advanced Workspace (流量梳理台)
A dedicated tab to manage and analyze interesting packets without cluttering your HTTP history.
一个独立的操作台，用于管理和分析感兴趣的数据包，避免污染主历史记录。

* **Smart Filtering:** Search packets using **Regex** or **Keywords**.
    (智能过滤：支持正则表达式或关键字快速检索数据包。)
* **Tagging System:** Custom tags and notes added in the Workspace will **auto-sync to Repeater tab titles**, making it easy to identify tabs.
    (标签联动：在梳理台修改的备注或标签，会自动同步修改 Repeater 的标签页标题，便于识别。)
* **Quick Actions:** Support custom hotkeys for rapid marking.
    (快捷操作：支持自定义快捷键进行快速标记。)

### 2. Batch Operations (批量联动)
* **Batch Feed to Proxy:** Select multiple "valuable" packets and forward them to a local listening proxy (e.g., **Xray**, Rad) for targeted fuzzing.
    (批量投喂被动扫描：选中多个有价值的数据包，一键转发给本地监听器（如 Xray/Rad 挂的代理）进行定向漏洞 Fuzz。)
* **Batch to Repeater/Intruder:** Send multiple selected requests to Repeater or Intruder simultaneously.
    (批量发送：支持批量发送数据包至重发器或攻击器。)

### 3. AI-Optimized Copy (AI 辅助复制模式)
* **Lite Copy (For AI/LLM):** Batch copy requests and response headers, but **replace the large response body with a size placeholder**.
    (AI 轻量复制：批量复制请求包和响应头，但**自动用“数据包大小占位符”替换庞大的响应体**。)
* **Benefit:** Analyze logic with ChatGPT/Claude without hitting token limits or extra costs.
    (优势：在保留核心逻辑的前提下极大节省 Token，完美适配 GPT/Claude 分析场景。)

---

## 📦 Installation / 安装说明

1.  **Download / 下载**:
    Download the latest `Entropy.jar` from the [Releases Page](../../../releases).
    (前往 Releases 页面下载最新的 `Entropy.jar`。)

2.  **Install / 安装**:
    * Open Burp Suite. (打开 Burp Suite。)
    * Go to **Extensions** -> **Installed**. (点击 Extensions -> Installed。)
    * Click **Add**. (点击 Add 按钮。)
    * Select **Java** as the extension type. (选择 Java 类型。)
    * Select the downloaded `Entropy.jar`. (选中下载好的 jar 文件。)

---

## 📖 Usage / 使用指南

1.  **Right-Click Menu (右键菜单)**:
    Right-click on any request in HTTP History to access the `Entropy` menu.
    (在 HTTP 历史记录中右键点击任意数据包，即可看到 `Entropy` 菜单。)

2.  **Send to Workspace (发送到梳理台)**:
    Move specific packets to the `Workspace` tab for regex analysis and tagging.
    (将特定数据包发送到 `Workspace` 标签页，进行正则分析和标记。)

3.  **Feed to Proxy (投喂到代理)**:
    Select multiple requests -> `Entropy` -> `Batch -> Feed to Proxy`.
    (选中多个请求 -> `Entropy` -> `Batch -> Feed to Proxy`，将其转发给 Xray 等扫描器。)
    * *Note: Configure the target proxy address in the `Config` tab.*
    * *(注：请在 `Config` 标签页配置目标代理地址。)*

4.  **Copy for AI (AI 复制)**:
    Select requests -> `Entropy` -> `Copy for AI (Lite - Size Only)`. Paste the result to ChatGPT.
    (选中请求 -> `Entropy` -> `Copy for AI (Lite - Size Only)`。将结果粘贴给 ChatGPT 进行分析。)

---

## 🛠 Compilation / 编译指南 (Optional)

If you want to build from source:
如果你想从源码编译：

```bash
# Clone the repository
git clone https://github.com/xgbtxy/Negentropy-Collective.git

# Navigate to the tool directory
cd Negentropy-Collective/Tools/Entropy

# Build with Gradle
./gradlew build
