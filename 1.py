import os
import shutil
import subprocess
import glob

# ==========================================
# 1. Java 源码 (V3 终极版 - Null Byte 防御)
# ==========================================
NEW_JAVA_CODE = r"""package burp;

import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;

public class BurpExtender implements IBurpExtender, IContextMenuFactory {

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private PrintWriter stdout;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.stdout = new PrintWriter(callbacks.getStdout(), true);
        
        callbacks.setExtensionName("Burp-Negentropy");
        callbacks.registerContextMenuFactory(this);
        
        stdout.println("[+] Burp-Negentropy (v1.3 Universal Fix) Loaded.");
        stdout.println("[+] Strategy: Null-Byte Detection active.");
    }

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        List<JMenuItem> menuList = new ArrayList<JMenuItem>();

        JMenuItem itemLite = new JMenuItem("Copy for AI (Lite - Smart Truncate)");
        itemLite.addActionListener(e -> copyMessages(invocation, false));
        
        JMenuItem itemFull = new JMenuItem("Copy for AI (Full - Headers & Body)");
        itemFull.addActionListener(e -> copyMessages(invocation, true));

        JMenuItem itemRepeater = new JMenuItem("Send to Repeater (Batch)");
        itemRepeater.addActionListener(e -> sendToRepeater(invocation));

        menuList.add(itemLite);
        menuList.add(itemFull);
        menuList.add(itemRepeater);
        return menuList;
    }

    private void copyMessages(IContextMenuInvocation invocation, boolean forceFullBody) {
        IHttpRequestResponse[] messages = invocation.getSelectedMessages();
        StringBuilder sb = new StringBuilder();

        for (IHttpRequestResponse message : messages) {
            try {
                byte[] reqBytes = message.getRequest();
                if (reqBytes != null) sb.append(helpers.bytesToString(reqBytes)).append("\n\n");

                byte[] resBytes = message.getResponse();
                if (resBytes == null) {
                    sb.append("(No Response)");
                } else {
                    IResponseInfo resInfo = helpers.analyzeResponse(resBytes);
                    int bodyOffset = resInfo.getBodyOffset();
                    byte[] bodyBytes = Arrays.copyOfRange(resBytes, bodyOffset, resBytes.length);

                    // V3 核心: Null Byte 检测
                    boolean hasNullByte = false;
                    int checkLen = Math.min(bodyBytes.length, 4096);
                    for (int i = 0; i < checkLen; i++) {
                        if (bodyBytes[i] == 0x00) { hasNullByte = true; break; }
                    }

                    // 辅助检测: Content-Type
                    boolean isHeaderBinary = false;
                    for (String h : resInfo.getHeaders()) {
                        String lower = h.toLowerCase();
                        if (lower.startsWith("content-type:") && 
                           (lower.contains("image/") || lower.contains("octet-stream") || 
                            lower.contains("zip") || lower.contains("pdf"))) {
                            isHeaderBinary = true;
                            break;
                        }
                    }

                    if (hasNullByte || isHeaderBinary) {
                        byte[] headerBytes = Arrays.copyOfRange(resBytes, 0, bodyOffset);
                        sb.append(helpers.bytesToString(headerBytes));
                        sb.append("\n\n{... BINARY DATA OMITTED (Null-Bytes Detected) ...}");
                    } else {
                        if (forceFullBody) {
                            sb.append(helpers.bytesToString(resBytes));
                        } else {
                            byte[] headerBytes = Arrays.copyOfRange(resBytes, 0, bodyOffset);
                            sb.append(helpers.bytesToString(headerBytes));
                            sb.append("\n\n{... Text Body Omitted (Size: " + bodyBytes.length + " bytes) ...}");
                        }
                    }
                }
                sb.append("\n\n==================================================\n\n");
            } catch (Exception e) {
                stdout.println("Error: " + e.getMessage());
            }
        }
        setClipboard(sb.toString());
    }

    private void sendToRepeater(IContextMenuInvocation invocation) {
        IHttpRequestResponse[] messages = invocation.getSelectedMessages();
        if (messages.length > 10) {
            int c = JOptionPane.showConfirmDialog(null, "Batch Send " + messages.length + "?", "Warning", JOptionPane.YES_NO_OPTION);
            if (c != JOptionPane.YES_OPTION) return;
        }
        for (IHttpRequestResponse msg : messages) {
            IHttpService s = msg.getHttpService();
            callbacks.sendToRepeater(s.getHost(), s.getPort(), "https".equalsIgnoreCase(s.getProtocol()), msg.getRequest(), null);
        }
    }

    private void setClipboard(String text) {
        StringSelection s = new StringSelection(text);
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(s, s);
    }
}
"""

# ==========================================
# 2. 自动化逻辑
# ==========================================
def main():
    root_dir = os.getcwd()
    ext_dir = os.path.join(root_dir, "Tools", "Burp-Extension")
    java_file = os.path.join(ext_dir, "src", "main", "java", "burp", "BurpExtender.java")
    
    print(f"🚀 启动智能构建流程...")

    # --- 1. 写入代码 ---
    print("\n[1/3] 更新 Java 源码...")
    if not os.path.exists(os.path.dirname(java_file)):
        print("❌ 错误: 目录结构不对，找不到 src 文件夹")
        return
    with open(java_file, "w", encoding="utf-8") as f:
        f.write(NEW_JAVA_CODE)
    print("✅ 源码已更新 (V3 Universal Fix)")

    # --- 2. 编译 ---
    print("\n[2/3] 执行 Gradle 编译...")
    try:
        # 先清理旧的构建文件，防止混淆
        subprocess.run(["gradle", "clean"], cwd=ext_dir, shell=True)
        # 开始构建
        res = subprocess.run(["gradle", "build"], cwd=ext_dir, shell=True)
        if res.returncode != 0:
            print("❌ 编译失败，请检查上方错误。")
            return
    except Exception as e:
        print(f"❌ 无法运行 Gradle: {e}")
        return

    # --- 3. 智能查找并移动 JAR ---
    print("\n[3/3] 查找并更新 JAR 包...")
    libs_dir = os.path.join(ext_dir, "build", "libs")
    
    # 获取 libs 目录下所有的 .jar 文件
    jar_files = glob.glob(os.path.join(libs_dir, "*.jar"))
    
    if not jar_files:
        print("❌ 错误: 编译成功但没有找到 .jar 文件！")
        return
    
    # 默认取第一个找到的 jar (通常只有一个)
    generated_jar_path = jar_files[0]
    generated_jar_name = os.path.basename(generated_jar_path)
    
    print(f"🔍 发现编译产物: {generated_jar_name}")
    
    # 目标路径
    final_jar_path = os.path.join(ext_dir, generated_jar_name)
    
    try:
        shutil.copy2(generated_jar_path, final_jar_path)
        print(f"📦 已将 {generated_jar_name} 部署到插件根目录")
        
        # 删除可能存在的旧名称 JAR (如果名字变了)
        for old_file in os.listdir(ext_dir):
            if old_file.endswith(".jar") and old_file != generated_jar_name:
                os.remove(os.path.join(ext_dir, old_file))
                print(f"🗑️ 已清理旧版本文件: {old_file}")
                
        print("-" * 50)
        print("🎉🎉🎉 构建完成！")
        print(f"💡 新文件名为: {generated_jar_name}")
        print("✅ 请去 Burp Suite 重新加载此文件。")
        
    except Exception as e:
        print(f"❌ 文件移动失败: {e}")

if __name__ == "__main__":
    main()