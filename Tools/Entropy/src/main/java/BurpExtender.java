import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.HighlightColor;
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
    public static Map<Character, String> TAG_MAP = new HashMap<>();

    // --- 快捷键配置 (QWER) ---
    public static char KEY_FEED = 'q';      
    public static char KEY_REPEATER = 'w';  
    public static char KEY_INTRUDER = 'e';  
    public static char KEY_COPY_LITE = 'c'; 
    public static char KEY_COPY_FULL = 'C'; 
    public static char KEY_CLEAR = 'd';     
    public static char KEY_DELETE = 'f';    

    // --- 代理配置 ---
    public static boolean PROXY_ENABLE = false;
    public static String PROXY_HOST = "127.0.0.1";
    public static int PROXY_PORT = 7777;
    public static Proxy.Type PROXY_TYPE = Proxy.Type.HTTP;

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        api.extension().setName("Entropy");
        trustAllHosts();
        initDefaultTags();

        JTabbedPane mainTabs = new JTabbedPane();
        mainTabs.addTab("Help (说明)", new HelpTab());
        
        workspaceTab = new WorkspaceTab(api, entries);
        mainTabs.addTab("Workspace (梳理台)", workspaceTab);
        
        mainTabs.addTab("Config (配置)", new ConfigTab());

        api.userInterface().registerSuiteTab("Entropy", mainTabs);
        api.userInterface().registerContextMenuItemsProvider(new EntropyContextMenu());

        api.logging().logToOutput("Entropy v13.1 Loaded. Strategic Workspace (Host Column + Dedupe) Ready.");
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
    // 公共工具方法
    // ========================================================================
    private static void exportToClipboard(List<HttpRequestResponse> messages, boolean isFullMode) {
        StringBuilder sb = new StringBuilder();
        for (HttpRequestResponse msg : messages) {
            if (msg.request() != null) sb.append(msg.request().toString()).append("\n\n");
            
            if (msg.response() == null) {
                sb.append("(No Response)");
            } else {
                HttpResponse res = msg.response();
                sb.append(res.headers().toString()).append("\n\n");
                
                int bodySize = res.body().length();

                if (!isFullMode) {
                    sb.append("{Lite Mode: Body Omitted - Size: ").append(bodySize).append(" bytes}");
                } else {
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

    // ========================================================================
    // 全局右键菜单 (Proxy History 等地方) - 移除快捷键提示
    // ========================================================================
    class EntropyContextMenu implements ContextMenuItemsProvider {
        @Override
        public List<Component> provideMenuItems(ContextMenuEvent event) {
            if (event.messageEditorRequestResponse().isPresent() || !event.selectedRequestResponses().isEmpty()) {
                List<Component> menuList = new ArrayList<>();

                JMenuItem itemSend = new JMenuItem("Send to Workspace (发送到梳理台)");
                itemSend.addActionListener(e -> {
                    List<HttpRequestResponse> reqs = getRequests(event);
                    executor.submit(() -> {
                        List<ApiEntry> newEntries = new ArrayList<>();
                        int startId = entries.size() + 1;
                        for (HttpRequestResponse rr : reqs) newEntries.add(new ApiEntry(startId++, rr));
                        SwingUtilities.invokeLater(() -> {
                            entries.addAll(newEntries);
                            if (workspaceTab != null) workspaceTab.refreshTable();
                        });
                    });
                });

                JMenuItem itemFeed = new JMenuItem("Batch -> Feed Proxy (投喂代理)");
                itemFeed.setFont(itemFeed.getFont().deriveFont(Font.BOLD));
                itemFeed.addActionListener(e -> doFeedProxyCheck(getRequests(event)));

                JMenu menuTag = new JMenu("Add Tag to History (原生标记)");
                List<Character> keys = new ArrayList<>(TAG_MAP.keySet());
                Collections.sort(keys);
                for (Character key : keys) {
                    String tag = TAG_MAP.get(key);
                    JMenuItem tagItem = new JMenuItem(tag);
                    tagItem.addActionListener(e -> {
                        List<HttpRequestResponse> reqs = getRequests(event);
                        for (HttpRequestResponse rr : reqs) {
                            String currentNotes = rr.annotations().notes();
                            if (currentNotes == null) currentNotes = "";
                            if (!currentNotes.contains(tag.trim())) {
                                rr.annotations().setNotes(tag.trim() + " " + currentNotes);
                                if (tag.contains("SQL")) rr.annotations().setHighlightColor(HighlightColor.RED);
                                else if (tag.contains("XSS")) rr.annotations().setHighlightColor(HighlightColor.BLUE);
                                else if (tag.contains("RCE")) rr.annotations().setHighlightColor(HighlightColor.ORANGE);
                                else rr.annotations().setHighlightColor(HighlightColor.YELLOW);
                            }
                        }
                    });
                    menuTag.add(tagItem);
                }
                JMenuItem clearTagItem = new JMenuItem("Clear Tags (清除标记)");
                clearTagItem.addActionListener(e -> {
                    for (HttpRequestResponse rr : getRequests(event)) {
                        rr.annotations().setNotes("");
                        rr.annotations().setHighlightColor(HighlightColor.NONE);
                    }
                });
                menuTag.addSeparator();
                menuTag.add(clearTagItem);

                JMenuItem itemAiLite = new JMenuItem("Copy Lite (AI复制-精简)");
                itemAiLite.addActionListener(e -> executor.submit(() -> exportToClipboard(getRequests(event), false)));

                JMenuItem itemAiFull = new JMenuItem("Copy Full (AI复制-完整)");
                itemAiFull.addActionListener(e -> executor.submit(() -> exportToClipboard(getRequests(event), true)));

                JMenuItem itemRep = new JMenuItem("Batch -> Repeater (批量重放)");
                itemRep.addActionListener(e -> {
                    for (HttpRequestResponse rr : getRequests(event)) api.repeater().sendToRepeater(rr.request());
                });

                JMenuItem itemIntruder = new JMenuItem("Batch -> Intruder (批量入侵)");
                itemIntruder.addActionListener(e -> {
                    for (HttpRequestResponse rr : getRequests(event)) api.intruder().sendToIntruder(rr.request());
                });

                menuList.add(itemSend);
                menuList.add(menuTag);
                menuList.add(new JSeparator());
                menuList.add(itemFeed);
                menuList.add(new JSeparator());
                menuList.add(itemRep);
                menuList.add(itemIntruder);
                menuList.add(new JSeparator());
                menuList.add(itemAiLite);
                menuList.add(itemAiFull);
                return menuList;
            }
            return null;
        }

        private List<HttpRequestResponse> getRequests(ContextMenuEvent event) {
            List<HttpRequestResponse> reqs = new ArrayList<>();
            if (event.messageEditorRequestResponse().isPresent()) {
                reqs.add(event.messageEditorRequestResponse().get().requestResponse());
            } else {
                reqs.addAll(event.selectedRequestResponses());
            }
            return reqs;
        }

        private void doFeedProxyCheck(List<HttpRequestResponse> reqs) {
            if (!BurpExtender.PROXY_ENABLE) {
                JOptionPane.showMessageDialog(null, "Proxy Disabled. Check Config tab.");
                return;
            }
            executor.submit(() -> {
                int count = 0;
                for (HttpRequestResponse rr : reqs) { if (sendToProxy(rr.request())) count++; }
                api.logging().logToOutput("Fed " + count + " requests to proxy.");
            });
        }
    }

    // ========================================================================
    // Workspace Tab (梳理台 - 增强版)
    // ========================================================================
    class WorkspaceTab extends JPanel {
        private final ApiTableModel tableModel;
        private final JTable table;
        private final JLabel countLabel; // 统计 Label

        public WorkspaceTab(MontoyaApi api, List<ApiEntry> entries) {
            setLayout(new BorderLayout());

            // 顶部面板：搜索 + 去重按钮
            JPanel topPanel = new JPanel(new BorderLayout());
            JPanel searchContainer = new JPanel(new BorderLayout());
            JTextField searchField = new JTextField();
            JCheckBox regexMode = new JCheckBox("Regex");
            searchContainer.add(new JLabel(" Search: "), BorderLayout.WEST);
            searchContainer.add(searchField, BorderLayout.CENTER);
            searchContainer.add(regexMode, BorderLayout.EAST);
            
            // 去重按钮
            JButton dedupeBtn = new JButton("Deduplicate (自动去重)");
            dedupeBtn.setToolTipText("Remove duplicates based on Host + Method + URL + Params");
            dedupeBtn.addActionListener(e -> deduplicate());

            topPanel.add(searchContainer, BorderLayout.CENTER);
            topPanel.add(dedupeBtn, BorderLayout.EAST);

            tableModel = new ApiTableModel();
            table = new JTable(tableModel);
            table.setRowHeight(25);
            table.setAutoCreateRowSorter(true);
            
            table.putClientProperty("JTable.autoStartsEdit", Boolean.FALSE); 
            table.setFocusable(true);

            // 设置列宽 (新增 Host 列)
            table.getColumnModel().getColumn(0).setPreferredWidth(40);  // ID
            table.getColumnModel().getColumn(1).setPreferredWidth(150); // Host
            table.getColumnModel().getColumn(2).setPreferredWidth(60);  // Method
            table.getColumnModel().getColumn(3).setPreferredWidth(300); // URL
            table.getColumnModel().getColumn(4).setPreferredWidth(150); // Tag
            table.getColumnModel().getColumn(5).setPreferredWidth(200); // Params

            // 键盘监听
            table.addKeyListener(new KeyAdapter() {
                @Override
                public void keyPressed(KeyEvent e) {
                    char key = e.getKeyChar(); 
                    if (key == BurpExtender.KEY_FEED) { doFeedProxy(); e.consume(); return; }
                    if (key == BurpExtender.KEY_REPEATER) { doBatchRepeater(); e.consume(); return; }
                    if (key == BurpExtender.KEY_INTRUDER) { doBatchIntruder(); e.consume(); return; }
                    if (key == BurpExtender.KEY_COPY_LITE) { doCopy(false); e.consume(); return; }
                    if (key == BurpExtender.KEY_COPY_FULL) { doCopy(true); e.consume(); return; }
                    if (Character.toLowerCase(key) == Character.toLowerCase(BurpExtender.KEY_DELETE)) { doDelete(); e.consume(); return; }
                    if (Character.toLowerCase(key) == Character.toLowerCase(BurpExtender.KEY_CLEAR)) { doClear(); e.consume(); return; }
                    if (BurpExtender.TAG_MAP.containsKey(Character.toLowerCase(key))) {
                        doTag(BurpExtender.TAG_MAP.get(Character.toLowerCase(key)));
                        e.consume();
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

            // 梳理台右键菜单 (保留快捷键提示)
            JPopupMenu popup = new JPopupMenu();
            JMenuItem feedItem = new JMenuItem("Batch -> Feed Proxy [" + BurpExtender.KEY_FEED + "]");
            feedItem.addActionListener(e -> doFeedProxy());
            JMenuItem repItem = new JMenuItem("Batch -> Repeater [" + BurpExtender.KEY_REPEATER + "]");
            repItem.addActionListener(e -> doBatchRepeater());
            JMenuItem intItem = new JMenuItem("Batch -> Intruder [" + BurpExtender.KEY_INTRUDER + "]");
            intItem.addActionListener(e -> doBatchIntruder());
            JMenuItem copyLite = new JMenuItem("Copy Lite [" + BurpExtender.KEY_COPY_LITE + "]");
            copyLite.addActionListener(e -> doCopy(false));
            JMenuItem copyFull = new JMenuItem("Copy Full [" + BurpExtender.KEY_COPY_FULL + "]");
            copyFull.addActionListener(e -> doCopy(true));
            JMenuItem delItem = new JMenuItem("Delete Row [" + BurpExtender.KEY_DELETE + "]");
            delItem.addActionListener(e -> doDelete());

            popup.add(feedItem); popup.addSeparator();
            popup.add(repItem); popup.add(intItem); popup.addSeparator();
            popup.add(copyLite); popup.add(copyFull); popup.addSeparator();
            popup.add(delItem);
            table.setComponentPopupMenu(popup);

            add(topPanel, BorderLayout.NORTH);
            add(new JScrollPane(table), BorderLayout.CENTER);
            
            // 底部面板：状态栏 + 统计
            JPanel bottomPanel = new JPanel(new BorderLayout());
            JLabel helpLabel = new JLabel("  [Keys] q:Feed | w:Rep | e:Int | c:Lite | C:Full | d:Clear | f:Del");
            helpLabel.setForeground(Color.GRAY);
            
            countLabel = new JLabel("Total: 0 requests  ");
            countLabel.setFont(countLabel.getFont().deriveFont(Font.BOLD));

            bottomPanel.add(helpLabel, BorderLayout.WEST);
            bottomPanel.add(countLabel, BorderLayout.EAST);
            add(bottomPanel, BorderLayout.SOUTH);
        }

        // --- 动作逻辑 ---
        
        // 核心：自动去重
        private void deduplicate() {
            if (entries.isEmpty()) return;
            Set<String> uniqueKeys = new HashSet<>();
            List<ApiEntry> uniqueEntries = new ArrayList<>();
            int removedCount = 0;

            for (ApiEntry entry : entries) {
                // 唯一标识：Host + Method + Path + Params
                String key = entry.host + "|" + entry.method + "|" + entry.path + "|" + entry.params;
                if (!uniqueKeys.contains(key)) {
                    uniqueKeys.add(key);
                    uniqueEntries.add(entry);
                } else {
                    removedCount++;
                }
            }
            
            if (removedCount > 0) {
                entries.clear();
                entries.addAll(uniqueEntries);
                refreshTable();
                JOptionPane.showMessageDialog(this, "Deduplication Complete.\nRemoved " + removedCount + " duplicates.");
            } else {
                JOptionPane.showMessageDialog(this, "No duplicates found.");
            }
        }

        private void doBatchRepeater() {
            for(int r : table.getSelectedRows()) {
                ApiEntry en = entries.get(table.convertRowIndexToModel(r));
                String name = en.tag.isEmpty() ? en.method + " " + shortPath(en.path) : en.tag;
                api.repeater().sendToRepeater(en.requestResponse.request(), name);
            }
        }
        private void doBatchIntruder() {
            for(int r : table.getSelectedRows()) {
                ApiEntry en = entries.get(table.convertRowIndexToModel(r));
                api.intruder().sendToIntruder(en.requestResponse.request());
            }
        }
        private void doFeedProxy() {
            if(!BurpExtender.PROXY_ENABLE) { JOptionPane.showMessageDialog(this, "Proxy Disabled"); return; }
            int[] rows = table.getSelectedRows();
            executor.submit(() -> {
               for(int r : rows) sendToProxy(entries.get(table.convertRowIndexToModel(r)).requestResponse.request());
            });
        }
        private void doCopy(boolean full) {
            List<HttpRequestResponse> list = new ArrayList<>();
            for(int r : table.getSelectedRows()) list.add(entries.get(table.convertRowIndexToModel(r)).requestResponse);
            executor.submit(() -> exportToClipboard(list, full));
        }
        private void doDelete() {
            int[] rows = table.getSelectedRows();
            List<Integer> idx = new ArrayList<>();
            for(int r : rows) idx.add(table.convertRowIndexToModel(r));
            idx.sort(Collections.reverseOrder());
            for(int i : idx) entries.remove((int)i); 
            refreshTable();
        }
        private void doClear() {
            for (int r : table.getSelectedRows()) entries.get(table.convertRowIndexToModel(r)).tag = "";
            refreshTable();
        }
        private void doTag(String tagText) {
            for (int r : table.getSelectedRows()) {
                ApiEntry en = entries.get(table.convertRowIndexToModel(r));
                if (!en.tag.contains(tagText.trim())) en.tag = tagText + en.tag;
            }
            refreshTable();
        }

        public void refreshTable() { 
            tableModel.fireTableDataChanged(); 
            // 更新统计数据
            countLabel.setText("Total: " + entries.size() + " requests  ");
        }
        
        class ApiTableModel extends AbstractTableModel {
            String[] cols = {"ID", "Host", "Method", "URL", "Tag (Edit)", "Params"};
            public int getRowCount() { return entries.size(); }
            public int getColumnCount() { return cols.length; }
            public String getColumnName(int c) { return cols[c]; }
            public boolean isCellEditable(int r, int c) { return c == 4; } // Tag is 4th col
            public Object getValueAt(int r, int c) {
                ApiEntry e = entries.get(r);
                switch(c) {
                    case 0: return e.id; 
                    case 1: return e.host; 
                    case 2: return e.method; 
                    case 3: return e.path; 
                    case 4: return e.tag; 
                    case 5: return e.params; 
                    default: return "";
                }
            }
            public void setValueAt(Object val, int r, int c) {
                if (c == 4) { entries.get(r).tag = (String) val; fireTableCellUpdated(r, c); }
            }
        }
    }

    // ========================================================================
    // Config Tab
    // ========================================================================
    class ConfigTab extends JPanel {
        private final DefaultTableModel model;

        public ConfigTab() {
            setLayout(new BorderLayout());
            setBorder(BorderFactory.createEmptyBorder(10,10,10,10));

            JPanel top = new JPanel();
            top.setLayout(new BoxLayout(top, BoxLayout.Y_AXIS));

            // 1. Shortcuts
            JPanel shortcuts = new JPanel(new FlowLayout(FlowLayout.LEFT));
            shortcuts.setBorder(BorderFactory.createTitledBorder("Shortcut Customization (QWER Layout)"));
            shortcuts.add(new JLabel("Feed(q):")); shortcuts.add(createKeyField(BurpExtender.KEY_FEED, k->BurpExtender.KEY_FEED=k));
            shortcuts.add(new JLabel("Rep(w):")); shortcuts.add(createKeyField(BurpExtender.KEY_REPEATER, k->BurpExtender.KEY_REPEATER=k));
            shortcuts.add(new JLabel("Intr(e):")); shortcuts.add(createKeyField(BurpExtender.KEY_INTRUDER, k->BurpExtender.KEY_INTRUDER=k));
            shortcuts.add(new JLabel("Lite(c):")); shortcuts.add(createKeyField(BurpExtender.KEY_COPY_LITE, k->BurpExtender.KEY_COPY_LITE=k));
            shortcuts.add(new JLabel("Full(C):")); shortcuts.add(createKeyField(BurpExtender.KEY_COPY_FULL, k->BurpExtender.KEY_COPY_FULL=k));
            shortcuts.add(new JLabel("Clear(d):")); shortcuts.add(createKeyField(BurpExtender.KEY_CLEAR, k->BurpExtender.KEY_CLEAR=k));
            shortcuts.add(new JLabel("Del(f):")); shortcuts.add(createKeyField(BurpExtender.KEY_DELETE, k->BurpExtender.KEY_DELETE=k));

            // 2. General
            JPanel basic = new JPanel(new FlowLayout(FlowLayout.LEFT));
            basic.setBorder(BorderFactory.createTitledBorder("General"));
            JCheckBox autoParam = new JCheckBox("Auto Extract Params");
            autoParam.setSelected(BurpExtender.AUTO_EXTRACT_PARAMS);
            autoParam.addActionListener(e -> BurpExtender.AUTO_EXTRACT_PARAMS = autoParam.isSelected());
            basic.add(autoParam);

            // 3. Proxy
            JPanel proxy = new JPanel(new FlowLayout(FlowLayout.LEFT));
            proxy.setBorder(BorderFactory.createTitledBorder("Passive Proxy"));
            JCheckBox pEnable = new JCheckBox("Enable");
            pEnable.setSelected(BurpExtender.PROXY_ENABLE);
            pEnable.addActionListener(e -> BurpExtender.PROXY_ENABLE = pEnable.isSelected());
            
            JTextField pHost = new JTextField(BurpExtender.PROXY_HOST, 10);
            pHost.addKeyListener(new KeyAdapter() { public void keyReleased(KeyEvent e) { BurpExtender.PROXY_HOST = pHost.getText().trim(); }});
            JTextField pPort = new JTextField(String.valueOf(BurpExtender.PROXY_PORT), 5);
            pPort.addKeyListener(new KeyAdapter() { public void keyReleased(KeyEvent e) { try{BurpExtender.PROXY_PORT = Integer.parseInt(pPort.getText().trim());}catch(Exception x){} }});
            JComboBox<String> pType = new JComboBox<>(new String[]{"HTTP", "SOCKS"});
            pType.addActionListener(e -> BurpExtender.PROXY_TYPE = "SOCKS".equals(pType.getSelectedItem()) ? Proxy.Type.SOCKS : Proxy.Type.HTTP);

            proxy.add(pEnable); proxy.add(new JLabel("Host:")); proxy.add(pHost); proxy.add(new JLabel("Port:")); proxy.add(pPort); proxy.add(pType);

            top.add(shortcuts);
            top.add(basic);
            top.add(proxy);
            add(top, BorderLayout.NORTH);

            // 4. Tag Table
            String[] headers = {"Key (Char)", "Tag Content"};
            model = new DefaultTableModel(headers, 0);
            JTable table = new JTable(model);
            refreshTable();
            add(new JScrollPane(table), BorderLayout.CENTER);

            JPanel btns = new JPanel(new FlowLayout(FlowLayout.LEFT));
            JButton addBtn = new JButton("Add Tag");
            addBtn.addActionListener(e -> model.addRow(new Object[]{"", "[Tag] "}));
            JButton delBtn = new JButton("Delete Tag");
            delBtn.addActionListener(e -> {
                int[] rows = table.getSelectedRows();
                for(int i=rows.length-1; i>=0; i--) model.removeRow(rows[i]);
                saveMap();
            });
            JButton saveBtn = new JButton("Apply Config");
            saveBtn.setFont(saveBtn.getFont().deriveFont(Font.BOLD));
            saveBtn.addActionListener(e -> { saveMap(); JOptionPane.showMessageDialog(this, "Config Applied!"); });

            btns.add(addBtn); btns.add(delBtn); btns.add(saveBtn);
            add(btns, BorderLayout.SOUTH);
        }

        private JTextField createKeyField(char initial, java.util.function.Consumer<Character> setter) {
            JTextField tf = new JTextField(String.valueOf(initial), 2);
            tf.addKeyListener(new KeyAdapter() {
                public void keyReleased(KeyEvent e) { if(!tf.getText().isEmpty()) setter.accept(tf.getText().charAt(0)); }
            });
            return tf;
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
                    "<h1>Entropy Manager (Strategic Edition)</h1>" +
                    "<h3>Workspace:</h3>" +
                    "<ul><li><b>Host Column:</b> Identify assets clearly.</li>" +
                    "<li><b>Deduplicate:</b> Remove identical requests (Host+Method+URL+Params).</li>" +
                    "<li><b>Counter:</b> Real-time request count at bottom.</li></ul>" +
                    "<h3>Shortcuts (Workspace Only):</h3>" +
                    "<ul>" +
                    "<li><b>q</b>: Feed to Proxy | <b>w</b>: Repeater | <b>e</b>: Intruder</li>" +
                    "<li><b>c</b>: Copy Lite | <b>C</b>: Copy Full</li>" +
                    "<li><b>d</b>: Clear Tag | <b>f</b>: Delete Row</li>" +
                    "</ul>" +
                    "</body></html>");
            add(new JScrollPane(ep));
        }
    }

    static class ApiEntry {
        int id; HttpRequestResponse requestResponse; String host, method, path, tag="", params;
        ApiEntry(int id, HttpRequestResponse rr) {
            this.id=id; this.requestResponse = rr; HttpRequest req = rr.request();
            this.host=req.httpService().host(); // 获取 Host
            this.method=req.method(); this.path=req.path();
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