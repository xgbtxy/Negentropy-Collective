import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.io.OutputStream;
import java.net.*;
import java.security.cert.X509Certificate;
import javax.net.ssl.*;
import java.util.*;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class BurpExtender implements BurpExtension {

    private MontoyaApi api;
    private final List<ApiEntry> entries = new ArrayList<>();
    private WorkspaceTab workspaceTab;
    private final ExecutorService executor = Executors.newFixedThreadPool(10);
    private static final Pattern JSON_PATTERN = Pattern.compile("\"(.*?)\"\\s*:");

    // --- 全局配置 ---
    public static boolean AUTO_EXTRACT_PARAMS = true;
    public static char CLEAR_KEY = 'd';
    public static char DELETE_KEY = 'f'; // 新增：删除键配置
    public static Map<Character, String> TAG_MAP = new HashMap<>();

    // --- 代理配置 ---
    public static boolean PROXY_ENABLE = false;
    public static String PROXY_HOST = "127.0.0.1";
    public static int PROXY_PORT = 7777;
    public static Proxy.Type PROXY_TYPE = Proxy.Type.HTTP;

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        api.extension().setName("Entropy"); // 极简名字
        trustAllHosts();
        initDefaultTags();

        JTabbedPane mainTabs = new JTabbedPane();
        mainTabs.addTab("Help (说明)", new HelpTab());
        
        workspaceTab = new WorkspaceTab(api, entries);
        mainTabs.addTab("Workspace (梳理台)", workspaceTab);
        
        mainTabs.addTab("Config (配置)", new ConfigTab());

        api.userInterface().registerSuiteTab("Entropy", mainTabs);
        api.userInterface().registerContextMenuItemsProvider(new EntropyContextMenu());

        api.logging().logToOutput("Entropy v11.2 Loaded. Delete Key: '" + DELETE_KEY + "'");
    }

    private void initDefaultTags() {
        TAG_MAP.put('1', "[SQL] ");
        TAG_MAP.put('2', "[XSS] ");
        TAG_MAP.put('3', "[IDOR] ");
        TAG_MAP.put('4', "[SSRF] ");
        TAG_MAP.put('5', "[RCE] ");
        TAG_MAP.put('6', "[Logic] ");
        TAG_MAP.put('7', "[Upload] ");
    }

    // ========================================================================
    // 右键菜单 (全局通用：支持 Proxy History, Repeater 等所有地方)
    // ========================================================================
    class EntropyContextMenu implements ContextMenuItemsProvider {
        @Override
        public List<Component> provideMenuItems(ContextMenuEvent event) {
            // 这个判断确保了在 Proxy History 选中多行时也能触发
            if (event.messageEditorRequestResponse().isPresent() || !event.selectedRequestResponses().isEmpty()) {
                List<Component> menuList = new ArrayList<>();

                // 1. 发送到 Entropy 工作台
                JMenuItem itemSend = new JMenuItem("Send to Workspace (发送到梳理台)");
                itemSend.addActionListener(e -> {
                    List<HttpRequest> reqs = getRequests(event);
                    executor.submit(() -> {
                        List<ApiEntry> newEntries = new ArrayList<>();
                        int startId = entries.size() + 1;
                        for (HttpRequest req : reqs) newEntries.add(new ApiEntry(startId++, req));
                        SwingUtilities.invokeLater(() -> {
                            entries.addAll(newEntries);
                            if (workspaceTab != null) workspaceTab.refreshTable();
                        });
                    });
                });

                // 2. 投喂到代理
                JMenuItem itemFeed = new JMenuItem("Batch -> Feed to Proxy (投喂到代理)");
                itemFeed.setFont(itemFeed.getFont().deriveFont(Font.BOLD));
                itemFeed.addActionListener(e -> {
                    if (!BurpExtender.PROXY_ENABLE) {
                        JOptionPane.showMessageDialog(null, "Proxy Disabled. Check Config tab.\n代理未开启，请检查配置页。");
                        return;
                    }
                    List<HttpRequest> reqs = getRequests(event);
                    executor.submit(() -> {
                        int count = 0;
                        for (HttpRequest req : reqs) { if (sendToProxy(req)) count++; }
                        api.logging().logToOutput("Fed " + count + " requests to proxy.");
                    });
                });

                // 3. AI 复制 (Lite - 仅大小)
                JMenuItem itemAiLite = new JMenuItem("Copy for AI (Lite - Size Only/精简版)");
                itemAiLite.addActionListener(e -> executor.submit(() -> copyForAI(event, false)));

                // 4. AI 复制 (Full - 防截断)
                JMenuItem itemAiFull = new JMenuItem("Copy for AI (Full - Text/完整版)");
                itemAiFull.addActionListener(e -> executor.submit(() -> copyForAI(event, true)));

                // 5. 批量 Repeater
                JMenuItem itemRep = new JMenuItem("Batch -> Repeater (批量重放)");
                itemRep.addActionListener(e -> {
                    List<HttpRequest> reqs = getRequests(event);
                    for (HttpRequest req : reqs) api.repeater().sendToRepeater(req);
                });

                // 6. 批量 Intruder
                JMenuItem itemIntruder = new JMenuItem("Batch -> Intruder (批量入侵)");
                itemIntruder.addActionListener(e -> {
                    List<HttpRequest> reqs = getRequests(event);
                    for (HttpRequest req : reqs) api.intruder().sendToIntruder(req);
                });

                menuList.add(itemSend);
                menuList.add(new JSeparator());
                menuList.add(itemFeed);
                menuList.add(new JSeparator());
                menuList.add(itemAiLite);
                menuList.add(itemAiFull);
                menuList.add(new JSeparator());
                menuList.add(itemRep);
                menuList.add(itemIntruder);
                
                return menuList;
            }
            return null;
        }

        private List<HttpRequest> getRequests(ContextMenuEvent event) {
            List<HttpRequest> reqs = new ArrayList<>();
            // 如果是在 Editor 里(单选)
            if (event.messageEditorRequestResponse().isPresent()) {
                reqs.add(event.messageEditorRequestResponse().get().requestResponse().request());
            } 
            // 如果是在 Proxy History 里(多选)
            else {
                event.selectedRequestResponses().forEach(rr -> reqs.add(rr.request()));
            }
            return reqs;
        }

        private void copyForAI(ContextMenuEvent event, boolean isFullMode) {
            StringBuilder sb = new StringBuilder();
            List<HttpRequestResponse> messages = new ArrayList<>();
            
            if (event.messageEditorRequestResponse().isPresent()) {
                 messages.add(event.messageEditorRequestResponse().get().requestResponse());
            } else {
                messages.addAll(event.selectedRequestResponses());
            }

            for (HttpRequestResponse msg : messages) {
                if (msg.request() != null) sb.append(msg.request().toString()).append("\n\n");
                
                if (msg.response() == null) {
                    sb.append("(No Response)");
                } else {
                    HttpResponse res = msg.response();
                    sb.append(res.headers().toString()).append("\n\n");
                    
                    int bodySize = res.body().length();

                    if (!isFullMode) {
                        // Lite 模式：记录大小，丢弃 Body
                        sb.append("{Lite Mode: Body Omitted - Size: ").append(bodySize).append(" bytes}");
                    } else {
                        // Full 模式：检查二进制和 0x00
                        boolean isBinaryHeader = false;
                        for (HttpHeader h : res.headers()) {
                            String val = h.value().toLowerCase();
                            if (h.name().equalsIgnoreCase("Content-Type") && 
                               (val.matches(".*(image|zip|pdf|octet|stream|video|audio).*"))) {
                                isBinaryHeader = true; break;
                            }
                        }

                        boolean hasNullByte = false;
                        if (!isBinaryHeader) {
                            ByteArray bodyBytes = res.body();
                            int checkLen = Math.min(bodyBytes.length(), 2048);
                            for (int i = 0; i < checkLen; i++) {
                                if (bodyBytes.getBytes()[i] == 0x00) { hasNullByte = true; break; }
                            }
                        }

                        if (isBinaryHeader || hasNullByte) {
                            sb.append("{BINARY/IMAGE OMITTED - Size: ").append(bodySize).append(" bytes}");
                        } else {
                            sb.append(res.bodyToString());
                        }
                    }
                }
                sb.append("\n\n==================================================\n\n");
            }
            
            StringSelection s = new StringSelection(sb.toString());
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(s, s);
        }
    }

    // ========================================================================
    // Workspace Tab (梳理台)
    // ========================================================================
    class WorkspaceTab extends JPanel {
        private final ApiTableModel tableModel;
        private final JTable table;

        public WorkspaceTab(MontoyaApi api, List<ApiEntry> entries) {
            setLayout(new BorderLayout());

            JPanel topPanel = new JPanel(new BorderLayout());
            JTextField searchField = new JTextField();
            JCheckBox regexMode = new JCheckBox("Regex (正则)");
            topPanel.add(new JLabel(" Search (搜索): "), BorderLayout.WEST);
            topPanel.add(searchField, BorderLayout.CENTER);
            topPanel.add(regexMode, BorderLayout.EAST);

            tableModel = new ApiTableModel();
            table = new JTable(tableModel);
            table.setRowHeight(25);
            table.setAutoCreateRowSorter(true);
            
            table.getColumnModel().getColumn(0).setPreferredWidth(40);
            table.getColumnModel().getColumn(1).setPreferredWidth(60);
            table.getColumnModel().getColumn(2).setPreferredWidth(300);
            table.getColumnModel().getColumn(3).setPreferredWidth(200);
            table.getColumnModel().getColumn(4).setPreferredWidth(200);

            // 键盘监听 (核心交互升级)
            table.addKeyListener(new KeyAdapter() {
                @Override
                public void keyPressed(KeyEvent e) {
                    char key = Character.toLowerCase(e.getKeyChar());
                    
                    // 1. 快捷删除 (自定义键)
                    if (key == Character.toLowerCase(BurpExtender.DELETE_KEY)) {
                        int[] selectedRows = table.getSelectedRows();
                        if (selectedRows.length > 0) {
                            // 使用安全的倒序删除，防止索引错乱
                            List<Integer> modelIndices = new ArrayList<>();
                            for (int viewRow : selectedRows) {
                                modelIndices.add(table.convertRowIndexToModel(viewRow));
                            }
                            modelIndices.sort(Collections.reverseOrder());
                            
                            for (int modelIndex : modelIndices) {
                                entries.remove(modelIndex);
                            }
                            tableModel.fireTableDataChanged();
                            e.consume();
                        }
                        return;
                    }

                    // 2. 清除键 (自定义键)
                    if (key == Character.toLowerCase(BurpExtender.CLEAR_KEY)) {
                        if (table.getSelectedRows().length > 0) {
                            for (int viewRow : table.getSelectedRows()) {
                                entries.get(table.convertRowIndexToModel(viewRow)).tag = "";
                            }
                            tableModel.fireTableDataChanged();
                            e.consume();
                        }
                        return;
                    }

                    // 3. 打标键
                    if (BurpExtender.TAG_MAP.containsKey(key)) {
                        String tagText = BurpExtender.TAG_MAP.get(key);
                        if (table.getSelectedRows().length > 0) {
                            for (int viewRow : table.getSelectedRows()) {
                                ApiEntry entry = entries.get(table.convertRowIndexToModel(viewRow));
                                if (!entry.tag.contains(tagText.trim())) entry.tag = tagText + entry.tag;
                            }
                            tableModel.fireTableDataChanged();
                            e.consume();
                        }
                    }
                }
            });

            // 过滤
            TableRowSorter<ApiTableModel> sorter = new TableRowSorter<>(tableModel);
            table.setRowSorter(sorter);
            KeyAdapter filterListener = new KeyAdapter() {
                public void keyReleased(KeyEvent e) {
                    String text = searchField.getText();
                    if (text.isEmpty()) sorter.setRowFilter(null);
                    else {
                        try {
                            String p = regexMode.isSelected() ? "(?i)" + text : "(?i)" + Pattern.quote(text);
                            sorter.setRowFilter(RowFilter.regexFilter(p));
                            searchField.setBackground(Color.WHITE);
                        } catch (Exception ex) { searchField.setBackground(Color.PINK); }
                    }
                }
            };
            searchField.addKeyListener(filterListener);
            regexMode.addActionListener(e -> filterListener.keyReleased(null));

            // 表格内部右键菜单
            JPopupMenu popup = new JPopupMenu();
            JMenuItem feedItem = new JMenuItem("Batch -> Feed to Proxy (投喂到代理)");
            feedItem.addActionListener(e -> {
                if(!BurpExtender.PROXY_ENABLE) { JOptionPane.showMessageDialog(this, "Proxy Disabled (代理未开启)"); return; }
                int[] rows = table.getSelectedRows();
                executor.submit(() -> {
                   for(int r : rows) sendToProxy(entries.get(table.convertRowIndexToModel(r)).req);
                });
            });

            JMenuItem repItem = new JMenuItem("Batch -> Repeater (批量重放)");
            repItem.addActionListener(e -> {
                for(int r : table.getSelectedRows()) {
                    ApiEntry en = entries.get(table.convertRowIndexToModel(r));
                    String name = en.tag.isEmpty() ? en.method + " " + shortPath(en.path) : en.tag;
                    api.repeater().sendToRepeater(en.req, name);
                }
            });
            
            JMenuItem delItem = new JMenuItem("Delete Row (删除行)");
            delItem.addActionListener(e -> {
                int[] rows = table.getSelectedRows();
                // 同样使用安全的倒序删除
                List<Integer> modelIndices = new ArrayList<>();
                for (int r : rows) modelIndices.add(table.convertRowIndexToModel(r));
                modelIndices.sort(Collections.reverseOrder());
                for (int i : modelIndices) entries.remove(i);
                tableModel.fireTableDataChanged();
            });

            popup.add(feedItem);
            popup.add(repItem);
            popup.addSeparator();
            popup.add(delItem);
            table.setComponentPopupMenu(popup);

            add(topPanel, BorderLayout.NORTH);
            add(new JScrollPane(table), BorderLayout.CENTER);
            
            // 底部提示动态显示配置的按键
            JLabel status = new JLabel("  [Shortcuts] 1-7: Tag | '" + BurpExtender.CLEAR_KEY + "': Clear Name | '" + BurpExtender.DELETE_KEY + "': Delete Row | Regex Filter");
            status.setForeground(Color.GRAY);
            add(status, BorderLayout.SOUTH);
        }

        public void refreshTable() { tableModel.fireTableDataChanged(); }
        
        class ApiTableModel extends AbstractTableModel {
            String[] cols = {"ID", "Method", "URL", "Tag (Edit)", "Params"};
            public int getRowCount() { return entries.size(); }
            public int getColumnCount() { return cols.length; }
            public String getColumnName(int c) { return cols[c]; }
            public boolean isCellEditable(int r, int c) { return c == 3; }
            public Object getValueAt(int r, int c) {
                ApiEntry e = entries.get(r);
                switch(c) {
                    case 0: return e.id; case 1: return e.method; case 2: return e.path; case 3: return e.tag; case 4: return e.params; default: return "";
                }
            }
            public void setValueAt(Object val, int r, int c) {
                if (c == 3) { entries.get(r).tag = (String) val; fireTableCellUpdated(r, c); }
            }
        }
    }

    // ========================================================================
    // Config Tab (配置)
    // ========================================================================
    class ConfigTab extends JPanel {
        private final DefaultTableModel model;

        public ConfigTab() {
            setLayout(new BorderLayout());
            setBorder(BorderFactory.createEmptyBorder(10,10,10,10));

            JPanel top = new JPanel();
            top.setLayout(new BoxLayout(top, BoxLayout.Y_AXIS));

            // 1. 基础设置
            JPanel basic = new JPanel(new FlowLayout(FlowLayout.LEFT));
            basic.setBorder(BorderFactory.createTitledBorder("General (基础设置)"));
            JCheckBox autoParam = new JCheckBox("Auto Extract Params (自动提取参数)");
            autoParam.setSelected(BurpExtender.AUTO_EXTRACT_PARAMS);
            autoParam.addActionListener(e -> BurpExtender.AUTO_EXTRACT_PARAMS = autoParam.isSelected());
            
            JTextField clearKey = new JTextField(String.valueOf(BurpExtender.CLEAR_KEY), 2);
            clearKey.addKeyListener(new KeyAdapter() {
                public void keyReleased(KeyEvent e) { if(!clearKey.getText().isEmpty()) BurpExtender.CLEAR_KEY = clearKey.getText().charAt(0); }
            });

            JTextField deleteKey = new JTextField(String.valueOf(BurpExtender.DELETE_KEY), 2);
            deleteKey.addKeyListener(new KeyAdapter() {
                public void keyReleased(KeyEvent e) { if(!deleteKey.getText().isEmpty()) BurpExtender.DELETE_KEY = deleteKey.getText().charAt(0); }
            });

            basic.add(autoParam);
            basic.add(new JLabel("  Clear Key (清除键):"));
            basic.add(clearKey);
            basic.add(new JLabel("  Delete Key (删除键):"));
            basic.add(deleteKey);

            // 2. 代理设置
            JPanel proxy = new JPanel(new FlowLayout(FlowLayout.LEFT));
            proxy.setBorder(BorderFactory.createTitledBorder("Passive Proxy (扫描器联动)"));
            JCheckBox pEnable = new JCheckBox("Enable (开启)");
            pEnable.setSelected(BurpExtender.PROXY_ENABLE);
            pEnable.addActionListener(e -> BurpExtender.PROXY_ENABLE = pEnable.isSelected());
            
            JTextField pHost = new JTextField(BurpExtender.PROXY_HOST, 10);
            pHost.addKeyListener(new KeyAdapter() { public void keyReleased(KeyEvent e) { BurpExtender.PROXY_HOST = pHost.getText().trim(); }});
            
            JTextField pPort = new JTextField(String.valueOf(BurpExtender.PROXY_PORT), 5);
            pPort.addKeyListener(new KeyAdapter() { public void keyReleased(KeyEvent e) { try{BurpExtender.PROXY_PORT = Integer.parseInt(pPort.getText().trim());}catch(Exception x){} }});
            
            JComboBox<String> pType = new JComboBox<>(new String[]{"HTTP", "SOCKS"});
            pType.addActionListener(e -> BurpExtender.PROXY_TYPE = "SOCKS".equals(pType.getSelectedItem()) ? Proxy.Type.SOCKS : Proxy.Type.HTTP);

            proxy.add(pEnable);
            proxy.add(new JLabel("Host:")); proxy.add(pHost);
            proxy.add(new JLabel("Port:")); proxy.add(pPort);
            proxy.add(pType);

            top.add(basic);
            top.add(proxy);
            add(top, BorderLayout.NORTH);

            // 3. 快捷键表格
            String[] headers = {"Key (按键)", "Tag Content (标签内容)"};
            model = new DefaultTableModel(headers, 0);
            JTable table = new JTable(model);
            refreshTable();
            add(new JScrollPane(table), BorderLayout.CENTER);

            // 按钮
            JPanel btns = new JPanel(new FlowLayout(FlowLayout.LEFT));
            JButton addBtn = new JButton("Add (添加)");
            addBtn.addActionListener(e -> model.addRow(new Object[]{"", "[Tag] "}));
            JButton delBtn = new JButton("Delete (删除)");
            delBtn.addActionListener(e -> {
                int[] rows = table.getSelectedRows();
                for(int i=rows.length-1; i>=0; i--) model.removeRow(rows[i]);
                saveMap();
            });
            JButton saveBtn = new JButton("Apply Config (保存配置)");
            saveBtn.setFont(saveBtn.getFont().deriveFont(Font.BOLD));
            saveBtn.addActionListener(e -> { saveMap(); JOptionPane.showMessageDialog(this, "Config Saved!"); });

            btns.add(addBtn); btns.add(delBtn); btns.add(saveBtn);
            add(btns, BorderLayout.SOUTH);
        }

        void refreshTable() {
            model.setRowCount(0);
            BurpExtender.TAG_MAP.forEach((k,v) -> model.addRow(new Object[]{k+"", v}));
        }

        void saveMap() {
            BurpExtender.TAG_MAP.clear();
            for(int i=0; i<model.getRowCount(); i++) {
                String k = (String)model.getValueAt(i,0);
                String v = (String)model.getValueAt(i,1);
                if(k!=null && !k.isEmpty()) BurpExtender.TAG_MAP.put(k.toLowerCase().charAt(0), v);
            }
        }
    }

    class HelpTab extends JPanel {
        public HelpTab() {
            setLayout(new BorderLayout());
            JEditorPane ep = new JEditorPane();
            ep.setContentType("text/html");
            ep.setEditable(false);
            ep.setText("<html><body style='font-family:sans-serif;padding:15px;'>" +
                    "<h1>Entropy Manager</h1>" +
                    "<p>Turn Chaos into Order. (从混乱到有序)</p>" +
                    "<h3>Features (功能):</h3>" +
                    "<ul>" +
                    "<li><b>Workspace (梳理台):</b> The 'Low Entropy' zone. Only keep valuable assets here.<br>低熵工作区，只保留有价值的资产。</li>" +
                    "<li><b>Shortcuts (快捷键):</b><br>- Press <b>1-7</b>: Tag (打标签)<br>- Press <b>d</b>: Clear Name (清空标签)<br>- Press <b>f</b>: Delete Row (删除行)<br>(Keys 'd' and 'f' are customizable in Config)</li>" +
                    "<li><b>Proxy Linkage (代理联动):</b> Right click -> <b>Feed to Proxy</b> to send requests to Xray/Rad passively.<br>右键投喂给被动扫描器。</li>" +
                    "<li><b>AI Copy (AI复制):</b> Lite mode records size only. Full mode keeps text safe.<br>精简模式只记录大小，全量模式保留文本并防截断。</li>" +
                    "</ul>" +
                    "</body></html>");
            add(new JScrollPane(ep));
        }
    }

    static class ApiEntry {
        int id; HttpRequest req; String method, path, tag="", params;
        ApiEntry(int id, HttpRequest req) {
            this.id=id; this.req=req; this.method=req.method(); this.path=req.path();
            this.params = BurpExtender.AUTO_EXTRACT_PARAMS ? extract(req) : "";
        }
    }

    static String extract(HttpRequest req) {
        Set<String> keys = new LinkedHashSet<>();
        if (req.query()!=null) Arrays.stream(req.query().split("&")).filter(s->s.contains("=")).forEach(s->keys.add(s.split("=")[0]));
        String body = req.bodyToString();
        if(body!=null && body.trim().startsWith("{")) {
            Matcher m = JSON_PATTERN.matcher(body);
            int c=0; while(m.find() && c++<5) keys.add(m.group(1));
        } else if ("POST".equalsIgnoreCase(req.method()) && body!=null) {
            Arrays.stream(body.split("&")).filter(s->s.contains("=")).forEach(s->keys.add(s.split("=")[0]));
        }
        return String.join(", ", keys);
    }
    
    static String shortPath(String p) { return p.length()>20 && p.lastIndexOf("/")>0 ? ".."+p.substring(p.lastIndexOf("/")) : p; }
    
    private boolean sendToProxy(HttpRequest req) {
        try {
            Proxy proxy = new Proxy(BurpExtender.PROXY_TYPE, new InetSocketAddress(BurpExtender.PROXY_HOST, BurpExtender.PROXY_PORT));
            HttpURLConnection conn = (HttpURLConnection) new URL(req.url()).openConnection(proxy);
            conn.setRequestMethod(req.method());
            conn.setDoOutput(req.body().length()>0);
            req.headers().stream().filter(h->!h.name().equalsIgnoreCase("Content-Length")).forEach(h->conn.addRequestProperty(h.name(), h.value()));
            if(req.body().length()>0) try(OutputStream os=conn.getOutputStream()){os.write(req.body().getBytes());}
            conn.getResponseCode(); return true;
        } catch(Exception e) { return false; }
    }

    private void trustAllHosts() {
        try {
            SSLContext sc = SSLContext.getInstance("TLS");
            sc.init(null, new TrustManager[]{new X509TrustManager(){
                public X509Certificate[] getAcceptedIssuers(){return null;}
                public void checkClientTrusted(X509Certificate[] c,String a){}
                public void checkServerTrusted(X509Certificate[] c,String a){}
            }}, new java.security.SecureRandom());
            HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
            HttpsURLConnection.setDefaultHostnameVerifier((h,s)->true);
        } catch(Exception e){}
    }
}