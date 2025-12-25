
package burp;

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
        
        callbacks.setExtensionName("AI Helper & Batch Tools");
        callbacks.registerContextMenuFactory(this);
        
        stdout.println("插件加载成功：AI 复制增强 & 批量重发工具已就绪。");
    }

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        List<JMenuItem> menuList = new ArrayList<JMenuItem>();

        // --- 功能 1: AI 复制 (精简版 - 推荐) ---
        JMenuItem itemLite = new JMenuItem("Copy for AI (Lite - Headers Only)");
        itemLite.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                copyMessages(invocation, false);
            }
        });
        
        // --- 功能 2: AI 复制 (完整版) ---
        JMenuItem itemFull = new JMenuItem("Copy for AI (Full - Raw Data)");
        itemFull.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                copyMessages(invocation, true);
            }
        });

        // --- 功能 3: 批量发送到 Repeater ---
        JMenuItem itemRepeater = new JMenuItem("Send to Repeater (Batch)");
        itemRepeater.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                sendToRepeater(invocation);
            }
        });

        // --- 功能 4: 批量发送到 Intruder ---
        JMenuItem itemIntruder = new JMenuItem("Send to Intruder");
        itemIntruder.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                sendToIntruder(invocation);
            }
        });

        menuList.add(itemLite);
        menuList.add(itemFull);
        // menuList.add(new javax.swing.JSeparator()); // 删除此行以修复编译错误
        menuList.add(itemRepeater);
        menuList.add(itemIntruder);
        
        return menuList;
    }

    private void copyMessages(IContextMenuInvocation invocation, boolean includeBody) {
        IHttpRequestResponse[] messages = invocation.getSelectedMessages();
        StringBuilder sb = new StringBuilder();

        for (IHttpRequestResponse message : messages) {
            try {
                // Request (Always Full)
                byte[] reqBytes = message.getRequest();
                if (reqBytes != null) {
                    sb.append(helpers.bytesToString(reqBytes)).append("\n\n");
                }

                // Response
                byte[] resBytes = message.getResponse();
                if (resBytes == null) {
                    sb.append("(No Response)");
                } else {
                    if (includeBody) {
                        sb.append(helpers.bytesToString(resBytes));
                    } else {
                        // Smart Cut: Headers Only
                        IResponseInfo resInfo = helpers.analyzeResponse(resBytes);
                        int bodyOffset = resInfo.getBodyOffset();
                        byte[] headerBytes = Arrays.copyOfRange(resBytes, 0, bodyOffset);
                        
                        sb.append(helpers.bytesToString(headerBytes));
                        sb.append("\n\n{... Response Body Omitted (Size: " + (resBytes.length - bodyOffset) + " bytes) ...}");
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
            int choice = JOptionPane.showConfirmDialog(null, 
                "选中了 " + messages.length + " 个请求，确定要全部发送到 Repeater 吗？", 
                "批量发送警告", JOptionPane.YES_NO_OPTION);
            if (choice != JOptionPane.YES_OPTION) return;
        }

        for (IHttpRequestResponse message : messages) {
            IHttpService service = message.getHttpService();
            boolean useHttps = "https".equalsIgnoreCase(service.getProtocol());
            callbacks.sendToRepeater(
                service.getHost(), 
                service.getPort(), 
                useHttps, 
                message.getRequest(), 
                null
            );
        }
    }

    private void sendToIntruder(IContextMenuInvocation invocation) {
        IHttpRequestResponse[] messages = invocation.getSelectedMessages();
        for (IHttpRequestResponse message : messages) {
            IHttpService service = message.getHttpService();
            boolean useHttps = "https".equalsIgnoreCase(service.getProtocol());
            callbacks.sendToIntruder(
                service.getHost(), 
                service.getPort(), 
                useHttps, 
                message.getRequest()
            );
        }
    }

    private void setClipboard(String text) {
        StringSelection selection = new StringSelection(text);
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(selection, selection);
    }
}
