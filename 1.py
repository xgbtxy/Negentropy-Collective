import os
import shutil
import subprocess
import glob

# ==========================================
# Java 源码 (V5 - 极速版: 移除所有弹窗警告)
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
// 移除了 JOptionPane，不再需要弹窗

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
        
        stdout.println("[+] Burp-Negentropy (v1.5 Silky Mode) Loaded.");
        stdout.println("[+] All confirmation dialogs removed. Use with caution.");
    }

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        List<JMenuItem> menuList = new ArrayList<JMenuItem>();

        JMenuItem itemLite = new JMenuItem("Copy for AI (Lite)");
        itemLite.addActionListener(e -> copyMessages(invocation, false));
        
        JMenuItem itemFull = new JMenuItem("Copy for AI (Full)");
        itemFull.addActionListener(e -> copyMessages(invocation, true));

        JMenuItem itemRepeater = new JMenuItem("Send to Repeater (Batch)");
        itemRepeater.addActionListener(e -> sendToRepeater(invocation));

        JMenuItem itemIntruder = new JMenuItem("Send to Intruder (Batch)");
        itemIntruder.addActionListener(e -> sendToIntruder(invocation));

        menuList.add(itemLite);
        menuList.add(itemFull);
        menuList.add(itemRepeater);
        menuList.add(itemIntruder);
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

                    // Null-Byte Detection
                    boolean hasNullByte = false;
                    int checkLen = Math.min(bodyBytes.length, 4096);
                    for (int i = 0; i < checkLen; i++) {
                        if (bodyBytes[i] == 0x00) { hasNullByte = true; break; }
                    }

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

    // 【修改】移除所有警告，直接发送
    private void sendToRepeater(IContextMenuInvocation invocation) {
        IHttpRequestResponse[] messages = invocation.getSelectedMessages();
        // No warnings, just speed.
        for (IHttpRequestResponse msg : messages) {
            IHttpService s = msg.getHttpService();
            callbacks.sendToRepeater(s.getHost(), s.getPort(), "https".equalsIgnoreCase(s.getProtocol()), msg.getRequest(), null);
        }
    }

    // 【修改】移除所有警告，直接发送
    private void sendToIntruder(IContextMenuInvocation invocation) {
        IHttpRequestResponse[] messages = invocation.getSelectedMessages();
        // No warnings, just speed.
        for (IHttpRequestResponse msg : messages) {
            IHttpService s = msg.getHttpService();
            callbacks.sendToIntruder(s.getHost(), s.getPort(), "https".equalsIgnoreCase(s.getProtocol()), msg.getRequest(), null);
        }
    }

    private void setClipboard(String text) {
        StringSelection s = new StringSelection(text);
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(s, s);
    }
}
"""

# ==========================================
# 自动化流程
# ==========================================
def main():
    root_dir = os.getcwd()
    ext_dir = os.path.join(root_dir, "Tools", "Burp-Extension")
    java_file = os.path.join(ext_dir, "src", "main", "java", "burp", "BurpExtender.java")
    
    print(f"🚀 启动极速版升级 (Remove Warnings)...")

    # 1. 写入代码
    with open(java_file, "w", encoding="utf-8") as f:
        f.write(NEW_JAVA_CODE)
    print("✅ 源码已更新 (无弹窗版)")

    # 2. 编译
    print("🔨 正在编译...")
    try:
        subprocess.run(["gradle", "clean"], cwd=ext_dir, shell=True)
        res = subprocess.run(["gradle", "build"], cwd=ext_dir, shell=True)
        if res.returncode != 0: return
    except Exception as e:
        print(e)
        return

    # 3. 更新 JAR
    libs_dir = os.path.join(ext_dir, "build", "libs")
    jar_files = glob.glob(os.path.join(libs_dir, "*.jar"))
    
    if jar_files:
        new_jar = jar_files[0]
        target = os.path.join(ext_dir, os.path.basename(new_jar))
        shutil.copy2(new_jar, target)
        
        # 清理旧包
        for old in os.listdir(ext_dir):
            if old.endswith(".jar") and old != os.path.basename(new_jar):
                os.remove(os.path.join(ext_dir, old))
                
        print("🎉 升级完成！去 Burp 享受丝滑吧。")
    else:
        print("❌ 编译失败，没找到 JAR。")

if __name__ == "__main__":
    main()