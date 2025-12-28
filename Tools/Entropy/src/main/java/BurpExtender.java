import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.MimeType;
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
import java.util.stream.Collectors;

public class BurpExtender implements BurpExtension {

    private MontoyaApi api;
    private final List<ApiEntry> entries = new ArrayList<>();
    private WorkspaceTab workspaceTab;
    private final ExecutorService executor = Executors.newFixedThreadPool(10);
    private static final Pattern JSON_PATTERN = Pattern.compile("\"(.*?)\"\\s*:");

    // --- 全局配置 ---
    public static boolean AUTO_EXTRACT_PARAMS = true;
    public static boolean ENABLE_SHORTCUTS = true; // 快捷键总开关
    public static Map<Character, String> TAG_MAP = new HashMap<>();

    // --- 快捷键配置 (支持 null) ---
    public static Character KEY_FEED = 'q';      
    public static Character KEY_REPEATER = 'w';  
    public static Character KEY_INTRUDER = 'e';  
    public static Character KEY_COPY_LITE = 'c'; 
    public static Character KEY_COPY_FULL = 'C'; 
    public static Character KEY_CLEAR = 'd';     
    public static Character KEY_DELETE = 'f';    

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

        api.logging().logToOutput("Entropy v14.1 Loaded. Bilingual UI & Shortcuts Ready.");
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
    // 右键菜单 (全局通用)
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
                JOptionPane.showMessageDialog(null, "Proxy Disabled. Check Config tab.\n代理未开启，请在配置页启用。");
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
    // Workspace Tab (梳理台)
    // ========================================================================
    class WorkspaceTab extends JPanel {
        private final ApiTableModel tableModel;
        private final JTable table;
        private final JLabel statusLabel;
        private final JComboBox<String> mimeFilter;

        public WorkspaceTab(MontoyaApi api, List<ApiEntry> entries) {
            setLayout(new BorderLayout());

            // 顶部
            JPanel topPanel = new JPanel(new BorderLayout());
            JPanel searchContainer = new JPanel(new FlowLayout(FlowLayout.LEFT));
            
            JTextField searchField = new JTextField(15);
            JCheckBox regexMode = new JCheckBox("Regex (正则)");
            String[] mimeTypes = {"All Types (全部)", "JSON", "HTML", "SCRIPT", "IMAGE", "XML", "CSS", "PLAIN", "OTHER"};
            mimeFilter = new JComboBox<>(mimeTypes);
            
            searchContainer.add(new JLabel("Search (搜索): "));
            searchContainer.add(searchField);
            searchContainer.add(regexMode);
            searchContainer.add(new JLabel(" |  MIME (类型): "));
            searchContainer.add(mimeFilter);

            JButton dedupeBtn = new JButton("Deduplicate (自动去重)");
            dedupeBtn.addActionListener(e -> deduplicate());

            topPanel.add(searchContainer, BorderLayout.WEST);
            topPanel.add(dedupeBtn, BorderLayout.EAST);

            // 表格
            tableModel = new ApiTableModel();
            table = new JTable(tableModel);
            table.setRowHeight(25);
            table.setAutoCreateRowSorter(true);
            table.putClientProperty("JTable.autoStartsEdit", Boolean.FALSE); 
            table.setFocusable(true);

            table.getColumnModel().getColumn(0).setPreferredWidth(30);  
            table.getColumnModel().getColumn(1).setPreferredWidth(120); 
            table.getColumnModel().getColumn(2).setPreferredWidth(50);  
            table.getColumnModel().getColumn(3).setPreferredWidth(250); 
            table.getColumnModel().getColumn(4).setPreferredWidth(50);  
            table.getColumnModel().getColumn(5).setPreferredWidth(100); 
            table.getColumnModel().getColumn(6).setPreferredWidth(150); 

            // 键盘监听
            table.addKeyListener(new KeyAdapter() {
                @Override
                public void keyPressed(KeyEvent e) {
                    if (!BurpExtender.ENABLE_SHORTCUTS) return;

                    char key = e.getKeyChar(); 
                    if (BurpExtender.KEY_FEED != null && key == BurpExtender.KEY_FEED) { doFeedProxy(); e.consume(); return; }
                    if (BurpExtender.KEY_REPEATER != null && key == BurpExtender.KEY_REPEATER) { doBatchRepeater(); e.consume(); return; }
                    if (BurpExtender.KEY_INTRUDER != null && key == BurpExtender.KEY_INTRUDER) { doBatchIntruder(); e.consume(); return; }
                    if (BurpExtender.KEY_COPY_LITE != null && key == BurpExtender.KEY_COPY_LITE) { doCopy(false); e.consume(); return; }
                    if (BurpExtender.KEY_COPY_FULL != null && key == BurpExtender.KEY_COPY_FULL) { doCopy(true); e.consume(); return; }
                    
                    if (BurpExtender.KEY_DELETE != null && Character.toLowerCase(key) == Character.toLowerCase(BurpExtender.KEY_DELETE)) { doDelete(); e.consume(); return; }
                    if (BurpExtender.KEY_CLEAR != null && Character.toLowerCase(key) == Character.toLowerCase(BurpExtender.KEY_CLEAR)) { doClear(); e.consume(); return; }

                    if (BurpExtender.TAG_MAP.containsKey(Character.toLowerCase(key))) {
                        doTag(BurpExtender.TAG_MAP.get(Character.toLowerCase(key)));
                        e.consume();
                    }
                }
            });

            // 过滤器
            TableRowSorter<ApiTableModel> sorter = new TableRowSorter<>(tableModel);
            table.setRowSorter(sorter);
            Runnable updateFilter = () -> {
                List<RowFilter<Object, Object>> filters = new ArrayList<>();
                String text = searchField.getText();
                if (!text.isEmpty()) {
                    try {
                        String p = regexMode.isSelected() ? "(?i)" + text : "(?i)" + Pattern.quote(text);
                        filters.add(RowFilter.regexFilter(p));
                        searchField.setBackground(Color.WHITE);
                    } catch (Exception ex) { searchField.setBackground(Color.PINK); }
                }
                String selectedMime = (String) mimeFilter.getSelectedItem();
                if (selectedMime != null && !selectedMime.startsWith("All")) {
                    filters.add(RowFilter.regexFilter(selectedMime, 4));
                }
                if (filters.isEmpty()) sorter.setRowFilter(null);
                else sorter.setRowFilter(RowFilter.andFilter(filters));
            };
            searchField.addKeyListener(new KeyAdapter() { public void keyReleased(KeyEvent e) { updateFilter.run(); }});
            regexMode.addActionListener(e -> updateFilter.run());
            mimeFilter.addActionListener(e -> updateFilter.run());

            // 右键菜单 (双语 + 快捷键提示)
            JPopupMenu popup = new JPopupMenu();
            
            String kFeed = BurpExtender.KEY_FEED == null ? "" : " [" + BurpExtender.KEY_FEED + "]";
            JMenuItem feedItem = new JMenuItem("Batch -> Feed Proxy (投喂代理)" + kFeed);
            feedItem.addActionListener(e -> doFeedProxy());

            String kRep = BurpExtender.KEY_REPEATER == null ? "" : " [" + BurpExtender.KEY_REPEATER + "]";
            JMenuItem repItem = new JMenuItem("Batch -> Repeater (批量重放)" + kRep);
            repItem.addActionListener(e -> doBatchRepeater());

            String kInt = BurpExtender.KEY_INTRUDER == null ? "" : " [" + BurpExtender.KEY_INTRUDER + "]";
            JMenuItem intItem = new JMenuItem("Batch -> Intruder (批量入侵)" + kInt);
            intItem.addActionListener(e -> doBatchIntruder());

            String kLite = BurpExtender.KEY_COPY_LITE == null ? "" : " [" + BurpExtender.KEY_COPY_LITE + "]";
            JMenuItem copyLite = new JMenuItem("Copy Lite (AI复制-精简)" + kLite);
            copyLite.addActionListener(e -> doCopy(false));

            String kFull = BurpExtender.KEY_COPY_FULL == null ? "" : " [" + BurpExtender.KEY_COPY_FULL + "]";
            JMenuItem copyFull = new JMenuItem("Copy Full (AI复制-完整)" + kFull);
            copyFull.addActionListener(e -> doCopy(true));
            
            String kDel = BurpExtender.KEY_DELETE == null ? "" : " [" + BurpExtender.KEY_DELETE + "]";
            JMenuItem delItem = new JMenuItem("Delete Row (删除行)" + kDel);
            delItem.addActionListener(e -> doDelete());

            popup.add(feedItem); popup.addSeparator();
            popup.add(repItem); popup.add(intItem); popup.addSeparator();
            popup.add(copyLite); popup.add(copyFull); popup.addSeparator();
            popup.add(delItem);
            table.setComponentPopupMenu(popup);

            add(topPanel, BorderLayout.NORTH);
            add(new JScrollPane(table), BorderLayout.CENTER);
            
            // 底部统计
            statusLabel = new JLabel(" Ready.");
            statusLabel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));
            statusLabel.setFont(new Font("Monospaced", Font.PLAIN, 12));
            add(statusLabel, BorderLayout.SOUTH);
        }

        private void deduplicate() {
            if (entries.isEmpty()) return;
            Set<String> uniqueKeys = new HashSet<>();
            List<ApiEntry> uniqueEntries = new ArrayList<>();
            int removedCount = 0;
            for (ApiEntry entry : entries) {
                String key = entry.host + "|" + entry.method + "|" + entry.path + "|" + entry.params + "|" + entry.mime;
                if (!uniqueKeys.contains(key)) { uniqueKeys.add(key); uniqueEntries.add(entry); } 
                else { removedCount++; }
            }
            if (removedCount > 0) {
                entries.clear();
                for (int i = 0; i < uniqueEntries.size(); i++) uniqueEntries.get(i).id = i + 1;
                entries.addAll(uniqueEntries);
                refreshTable();
                JOptionPane.showMessageDialog(this, "Removed " + removedCount + " duplicates.");
            } else { JOptionPane.showMessageDialog(this, "No duplicates."); }
        }

        private void doBatchRepeater() { for(int r : table.getSelectedRows()) { ApiEntry en = entries.get(table.convertRowIndexToModel(r)); api.repeater().sendToRepeater(en.requestResponse.request(), en.tag.isEmpty() ? en.path : en.tag); } }
        private void doBatchIntruder() { for(int r : table.getSelectedRows()) { ApiEntry en = entries.get(table.convertRowIndexToModel(r)); api.intruder().sendToIntruder(en.requestResponse.request()); } }
        private void doFeedProxy() {
            if(!BurpExtender.PROXY_ENABLE) { JOptionPane.showMessageDialog(this, "Proxy Disabled"); return; }
            int[] rows = table.getSelectedRows();
            executor.submit(() -> { for(int r : rows) sendToProxy(entries.get(table.convertRowIndexToModel(r)).requestResponse.request()); });
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
        private void doClear() { for (int r : table.getSelectedRows()) entries.get(table.convertRowIndexToModel(r)).tag = ""; refreshTable(); }
        private void doTag(String tagText) {
            for (int r : table.getSelectedRows()) {
                ApiEntry en = entries.get(table.convertRowIndexToModel(r));
                if (!en.tag.contains(tagText.trim())) en.tag = tagText + en.tag;
            }
            refreshTable();
        }

        public void refreshTable() { tableModel.fireTableDataChanged(); updateStats(); }

        private void updateStats() {
            if (entries.isEmpty()) { statusLabel.setText(" No data."); return; }
            try {
                long total = entries.size();
                Map<String, Long> counts = entries.stream()
                    .collect(Collectors.groupingBy(e -> e.mime == null ? "UNKNOWN" : e.mime, Collectors.counting()));
                StringBuilder sb = new StringBuilder();
                sb.append(" 📊 Total: ").append(total).append("  |  ");
                String[] priority = {"JSON", "HTML", "SCRIPT", "XML", "IMAGE"};
                for (String key : priority) {
                    if (counts.containsKey(key)) { sb.append(key).append(": ").append(counts.get(key)).append("  "); counts.remove(key); }
                }
                long other = counts.values().stream().mapToLong(Long::longValue).sum();
                if (other > 0) sb.append("Other: ").append(other);
                statusLabel.setText(sb.toString());
            } catch (Exception e) { statusLabel.setText(" Stats Error"); }
        }
        
        class ApiTableModel extends AbstractTableModel {
            String[] cols = {"ID", "Host (主机)", "Method (方法)", "URL (路径)", "MIME (类型)", "Tag (标签/编辑)", "Params (参数)"};
            public int getRowCount() { return entries.size(); }
            public int getColumnCount() { return cols.length; }
            public String getColumnName(int c) { return cols[c]; }
            public boolean isCellEditable(int r, int c) { return c == 5; }
            public Object getValueAt(int r, int c) {
                ApiEntry e = entries.get(r);
                switch(c) {
                    case 0: return e.id; case 1: return e.host; case 2: return e.method; case 3: return e.path; case 4: return e.mime; case 5: return e.tag; case 6: return e.params; default: return "";
                }
            }
            public void setValueAt(Object val, int r, int c) {
                if (c == 5) { entries.get(r).tag = (String) val; fireTableCellUpdated(r, c); }
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

            // Shortcuts
            JPanel shortcuts = new JPanel(new FlowLayout(FlowLayout.LEFT));
            shortcuts.setBorder(BorderFactory.createTitledBorder("Shortcut Customization (自定义快捷键 - 可留空禁用)"));
            
            JCheckBox enableKeys = new JCheckBox("Enable Shortcuts (开启快捷键)");
            enableKeys.setSelected(BurpExtender.ENABLE_SHORTCUTS);
            enableKeys.addActionListener(e -> BurpExtender.ENABLE_SHORTCUTS = enableKeys.isSelected());
            shortcuts.add(enableKeys);
            shortcuts.add(Box.createHorizontalStrut(10));

            shortcuts.add(new JLabel("Feed(投喂) [q]:")); shortcuts.add(createKeyField(BurpExtender.KEY_FEED, k->BurpExtender.KEY_FEED=k));
            shortcuts.add(new JLabel("Rep(重放) [w]:")); shortcuts.add(createKeyField(BurpExtender.KEY_REPEATER, k->BurpExtender.KEY_REPEATER=k));
            shortcuts.add(new JLabel("Intr(入侵) [e]:")); shortcuts.add(createKeyField(BurpExtender.KEY_INTRUDER, k->BurpExtender.KEY_INTRUDER=k));
            shortcuts.add(new JLabel("Lite(精简) [c]:")); shortcuts.add(createKeyField(BurpExtender.KEY_COPY_LITE, k->BurpExtender.KEY_COPY_LITE=k));
            shortcuts.add(new JLabel("Full(完整) [C]:")); shortcuts.add(createKeyField(BurpExtender.KEY_COPY_FULL, k->BurpExtender.KEY_COPY_FULL=k));
            shortcuts.add(new JLabel("Clear(清空) [d]:")); shortcuts.add(createKeyField(BurpExtender.KEY_CLEAR, k->BurpExtender.KEY_CLEAR=k));
            shortcuts.add(new JLabel("Del(删除) [f]:")); shortcuts.add(createKeyField(BurpExtender.KEY_DELETE, k->BurpExtender.KEY_DELETE=k));

            // General
            JPanel basic = new JPanel(new FlowLayout(FlowLayout.LEFT));
            basic.setBorder(BorderFactory.createTitledBorder("General (常规设置)"));
            JCheckBox autoParam = new JCheckBox("Auto Extract Params (自动提取参数)");
            autoParam.setSelected(BurpExtender.AUTO_EXTRACT_PARAMS);
            autoParam.addActionListener(e -> BurpExtender.AUTO_EXTRACT_PARAMS = autoParam.isSelected());
            basic.add(autoParam);

            // Proxy
            JPanel proxy = new JPanel(new FlowLayout(FlowLayout.LEFT));
            proxy.setBorder(BorderFactory.createTitledBorder("Passive Proxy (扫描器联动设置)"));
            JCheckBox pEnable = new JCheckBox("Enable (开启)");
            pEnable.setSelected(BurpExtender.PROXY_ENABLE);
            pEnable.addActionListener(e -> BurpExtender.PROXY_ENABLE = pEnable.isSelected());
            JTextField pHost = new JTextField(BurpExtender.PROXY_HOST, 10);
            pHost.addKeyListener(new KeyAdapter() { public void keyReleased(KeyEvent e) { BurpExtender.PROXY_HOST = pHost.getText().trim(); }});
            JTextField pPort = new JTextField(String.valueOf(BurpExtender.PROXY_PORT), 5);
            pPort.addKeyListener(new KeyAdapter() { public void keyReleased(KeyEvent e) { try{BurpExtender.PROXY_PORT = Integer.parseInt(pPort.getText().trim());}catch(Exception x){} }});
            JComboBox<String> pType = new JComboBox<>(new String[]{"HTTP", "SOCKS"});
            pType.addActionListener(e -> BurpExtender.PROXY_TYPE = "SOCKS".equals(pType.getSelectedItem()) ? Proxy.Type.SOCKS : Proxy.Type.HTTP);
            proxy.add(pEnable); proxy.add(new JLabel("Host:")); proxy.add(pHost); proxy.add(new JLabel("Port:")); proxy.add(pPort); proxy.add(pType);

            top.add(shortcuts); top.add(basic); top.add(proxy);
            add(top, BorderLayout.NORTH);

            // Tags
            String[] headers = {"Key (按键)", "Tag Content (标签内容)"};
            model = new DefaultTableModel(headers, 0);
            JTable table = new JTable(model);
            refreshTable();
            add(new JScrollPane(table), BorderLayout.CENTER);

            JPanel btns = new JPanel(new FlowLayout(FlowLayout.LEFT));
            JButton addBtn = new JButton("Add Tag (添加)"); addBtn.addActionListener(e -> model.addRow(new Object[]{"", "[Tag] "}));
            JButton delBtn = new JButton("Delete Tag (删除)"); delBtn.addActionListener(e -> { int[] rows = table.getSelectedRows(); for(int i=rows.length-1; i>=0; i--) model.removeRow(rows[i]); saveMap(); });
            JButton saveBtn = new JButton("Apply Config (保存配置)"); saveBtn.setFont(saveBtn.getFont().deriveFont(Font.BOLD)); saveBtn.addActionListener(e -> { saveMap(); JOptionPane.showMessageDialog(this, "Config Applied!"); });
            btns.add(addBtn); btns.add(delBtn); btns.add(saveBtn);
            add(btns, BorderLayout.SOUTH);
        }

        private JTextField createKeyField(Character initial, java.util.function.Consumer<Character> setter) {
            String val = initial == null ? "" : String.valueOf(initial);
            JTextField tf = new JTextField(val, 2);
            tf.addKeyListener(new KeyAdapter() {
                public void keyReleased(KeyEvent e) { 
                    String text = tf.getText();
                    if(text.isEmpty()) { setter.accept(null); } else { setter.accept(text.charAt(0)); }
                }
            });
            return tf;
        }
        void refreshTable() { model.setRowCount(0); BurpExtender.TAG_MAP.forEach((k,v) -> model.addRow(new Object[]{k+"", v})); }
        void saveMap() { BurpExtender.TAG_MAP.clear(); for(int i=0; i<model.getRowCount(); i++) { String k = (String)model.getValueAt(i,0); String v = (String)model.getValueAt(i,1); if(k!=null && !k.isEmpty()) BurpExtender.TAG_MAP.put(k.toLowerCase().charAt(0), v); } }
    }

    class HelpTab extends JPanel {
        public HelpTab() {
            setLayout(new BorderLayout());
            JEditorPane ep = new JEditorPane();
            ep.setContentType("text/html");
            ep.setEditable(false);
            ep.setText("<html><body style='font-family:sans-serif;padding:15px;'>" +
                    "<h1>Entropy Manager (Bilingual)</h1>" +
                    "<h3>Workspace (梳理台):</h3>" +
                    "<ul>" +
                    "<li><b>Dashboard (数据大屏):</b> Real-time stats by MIME type at the bottom.<br>底部实时显示各类型数据包数量 (JSON, HTML...)。</li>" +
                    "<li><b>Deduplicate (去重):</b> Remove identical requests (Host+Method+URL+Params).<br>一键去除重复请求。</li>" +
                    "</ul>" +
                    "<h3>Shortcuts (梳理台快捷键):</h3>" +
                    "<ul>" +
                    "<li><b>q</b>: Feed Proxy (投喂) | <b>w</b>: Repeater (重放) | <b>e</b>: Intruder (入侵)</li>" +
                    "<li><b>c</b>: Copy Lite (精简) | <b>C</b>: Copy Full (完整)</li>" +
                    "<li><b>d</b>: Clear Tag (清空) | <b>f</b>: Delete Row (删除)</li>" +
                    "<li><b>1-7</b>: Quick Tags (快速打标)</li>" +
                    "</ul>" +
                    "<p><i>* Keys are customizable & nullable in Config. (按键可在配置页修改或留空禁用)</i></p>" +
                    "</body></html>");
            add(new JScrollPane(ep));
        }
    }

    static class ApiEntry {
        int id; HttpRequestResponse requestResponse; String host, method, path, tag="", params, mime="UNKNOWN";
        ApiEntry(int id, HttpRequestResponse rr) {
            this.id=id; this.requestResponse = rr; HttpRequest req = rr.request();
            this.host=req.httpService().host();
            this.method=req.method(); this.path=req.path();
            this.params = BurpExtender.AUTO_EXTRACT_PARAMS ? extract(req) : "";
            if (rr.response() != null) {
                MimeType mt = rr.response().inferredMimeType();
                if (mt != null) this.mime = mt.name();
            }
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