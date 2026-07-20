package burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpMode;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.border.TitledBorder;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.table.AbstractTableModel;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;

public class VariableManager {
    private final MontoyaApi api;
    private final Object lock = new Object();
    private final List<String> variableNames = new ArrayList<>();
    private final Map<String, String> values = new ConcurrentHashMap<>();
    private final Map<String, VariableExtractionRule> rules = new ConcurrentHashMap<>();

    private boolean replacementMasterEnabled = true;
    private boolean replacementEnabled = true;
    private boolean replacementIntruderEnabled = true;
    private boolean replacementScannerEnabled = true;
    private boolean replacementProxyEnabled = false;
    private boolean extractionEnabled = true;
    private String refreshStatusCodes = "401, 403";

    // UI Components
    private JPanel mainPanel;
    private JTable variablesTable;
    private VariablesTableModel tableModel;
    private JTextArea valueTextArea;
    
    private JCheckBox replacementMasterCheckBox;
    private JCheckBox globalReplaceCheckBox;
    private JCheckBox intruderReplaceCheckBox;
    private JCheckBox scannerReplaceCheckBox;
    private JCheckBox proxyReplaceCheckBox;
    private JCheckBox globalExtractCheckBox;
    private JTextField refreshStatusCodesField;

    // Rule Panel Components
    private JCheckBox ruleEnabledCheckBox;
    private JTextField matchUrlField;
    private JComboBox<String> sourceComboBox;
    private JTextField regexField;
    private JButton updateRuleButton;

    // Refresh Panel Components
    private JLabel savedRequestLabel;
    private JButton refreshRequestButton;
    private JButton sendToRepeaterButton;
    private JButton editRequestButton;

    private boolean isUpdatingUI = false;

    public VariableManager(MontoyaApi api) {
        this.api = api;
        loadPreferences();
        createUI();
    }

    public Component getTabComponent() {
        return mainPanel;
    }

    public Map<String, String> getVariables() {
        synchronized (lock) {
            return new HashMap<>(values);
        }
    }

    public Map<String, VariableExtractionRule> getRules() {
        synchronized (lock) {
            return new HashMap<>(rules);
        }
    }

    public List<String> getVariableNames() {
        synchronized (lock) {
            return new ArrayList<>(variableNames);
        }
    }

    public boolean isReplacementMasterEnabled() {
        return replacementMasterEnabled;
    }

    public boolean isReplacementEnabled() {
        return replacementEnabled;
    }

    public boolean isReplacementIntruderEnabled() {
        return replacementIntruderEnabled;
    }

    public boolean isReplacementScannerEnabled() {
        return replacementScannerEnabled;
    }

    public boolean isReplacementProxyEnabled() {
        return replacementProxyEnabled;
    }

    public boolean isExtractionEnabled() {
        return extractionEnabled;
    }

    public Set<Integer> getRefreshStatusCodes() {
        Set<Integer> codes = new HashSet<>();
        try {
            String[] parts = refreshStatusCodes.split(",");
            for (String part : parts) {
                String trimmed = part.trim();
                if (!trimmed.isEmpty()) {
                    codes.add(Integer.parseInt(trimmed));
                }
            }
        } catch (Exception e) {
            codes.clear();
            codes.add(401);
            codes.add(403);
        }
        return codes;
    }

    public void updateVariableValue(String name, String value) {
        synchronized (lock) {
            values.put(name, value);
            savePreferences();
        }
        SwingUtilities.invokeLater(() -> {
            int row = variableNames.indexOf(name);
            if (row >= 0) {
                tableModel.fireTableCellUpdated(row, 1);
                // If this row is currently selected, update the text area as well
                int selectedRow = variablesTable.getSelectedRow();
                if (selectedRow == row) {
                    isUpdatingUI = true;
                    valueTextArea.setText(value);
                    isUpdatingUI = false;
                }
            }
        });
    }

    public void addOrUpdateExtractionRule(String name, String value, boolean ruleEnabled, String matchUrl, String source, 
                                          String regex, String reqBase64, String host, int port, boolean secure) {
        synchronized (lock) {
            if (!variableNames.contains(name)) {
                variableNames.add(name);
            }
            values.put(name, value);
            VariableExtractionRule rule = new VariableExtractionRule(ruleEnabled, matchUrl, source, regex, 
                    reqBase64, host, port, secure);
            rules.put(name, rule);
            savePreferences();
        }
        SwingUtilities.invokeLater(() -> {
            tableModel.fireTableDataChanged();
            // Highlight the row that was added or updated
            int row = variableNames.indexOf(name);
            if (row >= 0) {
                variablesTable.setRowSelectionInterval(row, row);
                updateDetailsPanel(row);
            }
        });
    }

    private void createUI() {
        mainPanel = new JPanel(new BorderLayout(10, 10));
        mainPanel.setBorder(new EmptyBorder(10, 10, 10, 10));

        // --- TOP GLOBAL SETTINGS PANEL ---
        JPanel topPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 15, 5));
        
        globalReplaceCheckBox = new JCheckBox("Repeater", replacementEnabled);
        globalReplaceCheckBox.setFont(new Font(globalReplaceCheckBox.getFont().getName(), Font.BOLD, 12));
        globalReplaceCheckBox.addActionListener(e -> {
            replacementEnabled = globalReplaceCheckBox.isSelected();
            savePreferences();
        });

        intruderReplaceCheckBox = new JCheckBox("Intruder", replacementIntruderEnabled);
        intruderReplaceCheckBox.setFont(new Font(intruderReplaceCheckBox.getFont().getName(), Font.BOLD, 12));
        intruderReplaceCheckBox.addActionListener(e -> {
            replacementIntruderEnabled = intruderReplaceCheckBox.isSelected();
            savePreferences();
        });

        scannerReplaceCheckBox = new JCheckBox("Scanner", replacementScannerEnabled);
        scannerReplaceCheckBox.setFont(new Font(scannerReplaceCheckBox.getFont().getName(), Font.BOLD, 12));
        scannerReplaceCheckBox.addActionListener(e -> {
            replacementScannerEnabled = scannerReplaceCheckBox.isSelected();
            savePreferences();
        });

        proxyReplaceCheckBox = new JCheckBox("Proxy", replacementProxyEnabled);
        proxyReplaceCheckBox.setFont(new Font(proxyReplaceCheckBox.getFont().getName(), Font.BOLD, 12));
        proxyReplaceCheckBox.addActionListener(e -> {
            replacementProxyEnabled = proxyReplaceCheckBox.isSelected();
            savePreferences();
        });

        // Set initial visibility of tool checkboxes based on master checkbox state
        globalReplaceCheckBox.setVisible(replacementMasterEnabled);
        intruderReplaceCheckBox.setVisible(replacementMasterEnabled);
        scannerReplaceCheckBox.setVisible(replacementMasterEnabled);
        proxyReplaceCheckBox.setVisible(replacementMasterEnabled);

        replacementMasterCheckBox = new JCheckBox("Enable Variable Replacement", replacementMasterEnabled);
        replacementMasterCheckBox.setFont(new Font(replacementMasterCheckBox.getFont().getName(), Font.BOLD, 12));
        replacementMasterCheckBox.addActionListener(e -> {
            replacementMasterEnabled = replacementMasterCheckBox.isSelected();
            boolean visible = replacementMasterEnabled;
            globalReplaceCheckBox.setVisible(visible);
            intruderReplaceCheckBox.setVisible(visible);
            scannerReplaceCheckBox.setVisible(visible);
            proxyReplaceCheckBox.setVisible(visible);
            savePreferences();
            topPanel.revalidate();
            topPanel.repaint();
        });

        globalExtractCheckBox = new JCheckBox("Enable Response Auto-Extraction", extractionEnabled);
        globalExtractCheckBox.setFont(new Font(globalExtractCheckBox.getFont().getName(), Font.BOLD, 12));
        globalExtractCheckBox.addActionListener(e -> {
            extractionEnabled = globalExtractCheckBox.isSelected();
            savePreferences();
        });

        topPanel.add(replacementMasterCheckBox);
        topPanel.add(globalReplaceCheckBox);
        topPanel.add(intruderReplaceCheckBox);
        topPanel.add(scannerReplaceCheckBox);
        topPanel.add(proxyReplaceCheckBox);
        
        // Custom vertical divider
        JSeparator separator = new JSeparator(JSeparator.VERTICAL);
        separator.setPreferredSize(new Dimension(3, 20));
        topPanel.add(separator);
        
        topPanel.add(globalExtractCheckBox);

        // Custom vertical divider 2
        JSeparator separator2 = new JSeparator(JSeparator.VERTICAL);
        separator2.setPreferredSize(new Dimension(3, 20));
        topPanel.add(separator2);

        topPanel.add(new JLabel("Refresh Status Codes:"));
        refreshStatusCodesField = new JTextField(refreshStatusCodes, 8);
        refreshStatusCodesField.getDocument().addDocumentListener(new SimpleDocumentListener(() -> {
            refreshStatusCodes = refreshStatusCodesField.getText();
            savePreferences();
        }));
        topPanel.add(refreshStatusCodesField);

        mainPanel.add(topPanel, BorderLayout.NORTH);

        // --- CENTER SPLIT PANE ---
        JSplitPane splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        splitPane.setDividerLocation(450);
        splitPane.setResizeWeight(0.4);

        // Left Side: Variables Table & Buttons
        JPanel leftPanel = new JPanel(new BorderLayout(5, 5));
        tableModel = new VariablesTableModel();
        variablesTable = new JTable(tableModel);
        variablesTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        variablesTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                int selectedRow = variablesTable.getSelectedRow();
                updateDetailsPanel(selectedRow);
            }
        });

        JScrollPane tableScrollPane = new JScrollPane(variablesTable);
        leftPanel.add(tableScrollPane, BorderLayout.CENTER);

        // Buttons Panel under Table
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 5));
        JButton addButton = new JButton("Add Variable");
        JButton deleteButton = new JButton("Delete Selected");
        JButton clearButton = new JButton("Clear All");

        addButton.addActionListener(e -> {
            String name = JOptionPane.showInputDialog(mainPanel, "Enter variable name:", "Add Variable", JOptionPane.PLAIN_MESSAGE);
            if (name != null && !name.trim().isEmpty()) {
                name = name.trim();
                synchronized (lock) {
                    if (variableNames.contains(name)) {
                        JOptionPane.showMessageDialog(mainPanel, "Variable already exists!", "Error", JOptionPane.ERROR_MESSAGE);
                        return;
                    }
                    variableNames.add(name);
                    values.put(name, "");
                    rules.put(name, new VariableExtractionRule());
                    savePreferences();
                }
                tableModel.fireTableDataChanged();
                int newRow = variableNames.indexOf(name);
                variablesTable.setRowSelectionInterval(newRow, newRow);
            }
        });

        deleteButton.addActionListener(e -> {
            int selectedRow = variablesTable.getSelectedRow();
            if (selectedRow >= 0) {
                String name = variableNames.get(selectedRow);
                synchronized (lock) {
                    variableNames.remove(selectedRow);
                    values.remove(name);
                    rules.remove(name);
                    savePreferences();
                }
                tableModel.fireTableDataChanged();
                valueTextArea.setText("");
                clearRuleFields();
            }
        });

        clearButton.addActionListener(e -> {
            int confirm = JOptionPane.showConfirmDialog(mainPanel, "Are you sure you want to clear all variables?", "Confirm Clear", JOptionPane.YES_NO_OPTION);
            if (confirm == JOptionPane.YES_OPTION) {
                synchronized (lock) {
                    variableNames.clear();
                    values.clear();
                    rules.clear();
                    savePreferences();
                }
                tableModel.fireTableDataChanged();
                valueTextArea.setText("");
                clearRuleFields();
            }
        });

        buttonPanel.add(addButton);
        buttonPanel.add(deleteButton);
        buttonPanel.add(clearButton);
        leftPanel.add(buttonPanel, BorderLayout.SOUTH);

        // Right Side: Variable Details, Regex Configuration, and Refresh Action
        JPanel rightPanel = new JPanel(new GridBagLayout());
        rightPanel.setBorder(new EmptyBorder(0, 10, 0, 0));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.fill = GridBagConstraints.BOTH;
        gbc.insets = new Insets(5, 5, 5, 5);

        // 1. Current Value JTextArea
        JPanel valuePanel = new JPanel(new BorderLayout(5, 5));
        valuePanel.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createEtchedBorder(),
                "Variable Value Editor (Paste long values here)",
                TitledBorder.LEFT,
                TitledBorder.TOP,
                new Font(mainPanel.getFont().getName(), Font.BOLD, 12)
        ));
        valueTextArea = new JTextArea(5, 20);
        valueTextArea.setLineWrap(true);
        valueTextArea.setWrapStyleWord(true);
        valueTextArea.getDocument().addDocumentListener(new DocumentListener() {
            @Override
            public void insertUpdate(DocumentEvent e) { updateValue(); }
            @Override
            public void removeUpdate(DocumentEvent e) { updateValue(); }
            @Override
            public void changedUpdate(DocumentEvent e) { updateValue(); }

            private void updateValue() {
                if (isUpdatingUI) return;
                int selectedRow = variablesTable.getSelectedRow();
                if (selectedRow >= 0) {
                    String name = variableNames.get(selectedRow);
                    String val = valueTextArea.getText();
                    synchronized (lock) {
                        values.put(name, val);
                        savePreferences();
                    }
                    tableModel.fireTableCellUpdated(selectedRow, 1);
                }
            }
        });
        valuePanel.add(new JScrollPane(valueTextArea), BorderLayout.CENTER);

        // 2. Extraction Rule Editor Panel
        JPanel rulePanel = new JPanel(new GridBagLayout());
        rulePanel.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createEtchedBorder(), 
                "Response Auto-Extraction Rule", 
                TitledBorder.LEFT, 
                TitledBorder.TOP, 
                new Font(mainPanel.getFont().getName(), Font.PLAIN, 12)
        ));
        
        GridBagConstraints rgbc = new GridBagConstraints();
        rgbc.fill = GridBagConstraints.HORIZONTAL;
        rgbc.insets = new Insets(4, 5, 4, 5);
        rgbc.gridx = 0;

        // Checkbox: Enable rule
        ruleEnabledCheckBox = new JCheckBox("Enable auto-extraction for this variable");
        ruleEnabledCheckBox.addActionListener(e -> updateActiveRuleFromUI());
        rgbc.gridy = 0;
        rgbc.gridwidth = 2;
        rulePanel.add(ruleEnabledCheckBox, rgbc);

        rgbc.gridwidth = 1;

        // Target URL/Path Filter
        rgbc.gridy = 1;
        rgbc.gridx = 0;
        rgbc.weightx = 0.0;
        rulePanel.add(new JLabel("Match URL/Path (Regex):"), rgbc);
        
        matchUrlField = new JTextField();
        matchUrlField.getDocument().addDocumentListener(new SimpleDocumentListener(this::updateActiveRuleFromUI));
        rgbc.gridx = 1;
        rgbc.weightx = 1.0;
        rulePanel.add(matchUrlField, rgbc);

        // Extract From Source JComboBox
        rgbc.gridy = 2;
        rgbc.gridx = 0;
        rgbc.weightx = 0.0;
        rulePanel.add(new JLabel("Extract From:"), rgbc);

        sourceComboBox = new JComboBox<>(new String[]{"Response Body", "Response Headers"});
        sourceComboBox.addActionListener(e -> updateActiveRuleFromUI());
        rgbc.gridx = 1;
        rgbc.weightx = 1.0;
        rulePanel.add(sourceComboBox, rgbc);

        // Regex Pattern
        rgbc.gridy = 3;
        rgbc.gridx = 0;
        rgbc.weightx = 0.0;
        rulePanel.add(new JLabel("Regex (with 1 capture group):"), rgbc);

        regexField = new JTextField();
        regexField.getDocument().addDocumentListener(new SimpleDocumentListener(this::updateActiveRuleFromUI));
        rgbc.gridx = 1;
        rgbc.weightx = 1.0;
        rulePanel.add(regexField, rgbc);

        // Update Rule from Response Button (Row 4)
        rgbc.gridy = 4;
        rgbc.gridx = 0;
        rgbc.gridwidth = 2;
        updateRuleButton = new JButton("Update Rule from Response...");
        updateRuleButton.addActionListener(e -> triggerUpdateRuleFromResponse());
        rulePanel.add(updateRuleButton, rgbc);

        rgbc.gridwidth = 1; // reset

        // 3. Refresh Action Panel (background request sender, edit request & send to repeater)
        JPanel refreshPanel = new JPanel(new BorderLayout(5, 5));
        refreshPanel.setBorder(BorderFactory.createTitledBorder("Token Refresh Request"));
        
        savedRequestLabel = new JLabel("Saved Request: None");
        savedRequestLabel.setFont(new Font(savedRequestLabel.getFont().getName(), Font.ITALIC, 11));
        savedRequestLabel.setBorder(new EmptyBorder(5, 10, 5, 10));
        refreshPanel.add(savedRequestLabel, BorderLayout.NORTH);

        JPanel refreshButtonsPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 5));
        
        refreshRequestButton = new JButton("Refresh Variable");
        refreshRequestButton.addActionListener(e -> triggerBackgroundRefresh());
        
        sendToRepeaterButton = new JButton("Send to Repeater");
        sendToRepeaterButton.addActionListener(e -> triggerSendToRepeater());

        editRequestButton = new JButton("Edit Request");
        editRequestButton.addActionListener(e -> showEditRequestDialog());

        refreshButtonsPanel.add(refreshRequestButton);
        refreshButtonsPanel.add(sendToRepeaterButton);
        refreshButtonsPanel.add(editRequestButton);
        refreshPanel.add(refreshButtonsPanel, BorderLayout.CENTER);

        // ADD PANES TO THE DETAILS PANEL IN THE SPECIFIED LAYOUT POSITIONS:
        // Refresh Panel (Row 0) - height adjusted to content
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.weightx = 1.0;
        gbc.weighty = 0.0;
        rightPanel.add(refreshPanel, gbc);

        // Extraction Rule Panel (Row 1) - height adjusted to content
        gbc.gridx = 0;
        gbc.gridy = 1;
        gbc.weightx = 1.0;
        gbc.weighty = 0.0;
        rightPanel.add(rulePanel, gbc);

        // Value Editor Panel (Row 2) - expands to occupy all remaining space
        gbc.gridx = 0;
        gbc.gridy = 2;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        rightPanel.add(valuePanel, gbc);

        splitPane.setLeftComponent(leftPanel);
        splitPane.setRightComponent(rightPanel);
        mainPanel.add(splitPane, BorderLayout.CENTER);

        // --- FOOTER INSTRUCTIONS ---
        JLabel footerLabel = new JLabel("Usage: Define variables, use {{variable_name}} in Repeater/Intruder/Scanner. Highlight response, right-click -> Assign to Variable to automate.");
        footerLabel.setBorder(new EmptyBorder(5, 5, 5, 5));
        mainPanel.add(footerLabel, BorderLayout.SOUTH);

        // Disable details until selection
        updateDetailsPanel(-1);
    }

    private void updateDetailsPanel(int selectedRow) {
        if (selectedRow < 0) {
            isUpdatingUI = true;
            valueTextArea.setText("");
            valueTextArea.setEnabled(false);
            ruleEnabledCheckBox.setSelected(false);
            ruleEnabledCheckBox.setEnabled(false);
            matchUrlField.setText("");
            matchUrlField.setEnabled(false);
            sourceComboBox.setSelectedIndex(0);
            sourceComboBox.setEnabled(false);
            regexField.setText("");
            regexField.setEnabled(false);
            updateRuleButton.setEnabled(false);
            savedRequestLabel.setText("Saved Request: None");
            refreshRequestButton.setEnabled(false);
            sendToRepeaterButton.setEnabled(false);
            editRequestButton.setEnabled(false);
            isUpdatingUI = false;
            return;
        }

        String name = variableNames.get(selectedRow);
        String val = values.getOrDefault(name, "");
        VariableExtractionRule rule = rules.getOrDefault(name, new VariableExtractionRule());

        isUpdatingUI = true;
        valueTextArea.setText(val);
        valueTextArea.setEnabled(true);

        ruleEnabledCheckBox.setEnabled(true);
        ruleEnabledCheckBox.setSelected(rule.isEnabled());

        matchUrlField.setEnabled(true);
        matchUrlField.setText(rule.getMatchUrl());

        sourceComboBox.setEnabled(true);
        if ("headers".equalsIgnoreCase(rule.getSource())) {
            sourceComboBox.setSelectedIndex(1);
        } else {
            sourceComboBox.setSelectedIndex(0);
        }

        regexField.setEnabled(true);
        regexField.setText(rule.getRegex());

        // Update refresh request details
        if (rule.getSavedRequestBase64() == null || rule.getSavedRequestBase64().isEmpty()) {
            savedRequestLabel.setText("Saved Request: None");
            refreshRequestButton.setEnabled(false);
            sendToRepeaterButton.setEnabled(false);
            editRequestButton.setEnabled(false);
            updateRuleButton.setEnabled(false);
        } else {
            try {
                byte[] requestBytes = Base64.getDecoder().decode(rule.getSavedRequestBase64());
                HttpRequest savedReq = HttpRequest.httpRequest(ByteArray.byteArray(requestBytes));
                savedRequestLabel.setText("Saved Request: " + savedReq.method() + " " + savedReq.path());
                refreshRequestButton.setEnabled(true);
                sendToRepeaterButton.setEnabled(true);
                editRequestButton.setEnabled(true);
                updateRuleButton.setEnabled(true);
            } catch (Exception e) {
                savedRequestLabel.setText("Saved Request: Error parsing request data");
                refreshRequestButton.setEnabled(false);
                sendToRepeaterButton.setEnabled(false);
                editRequestButton.setEnabled(false);
                updateRuleButton.setEnabled(false);
            }
        }
        isUpdatingUI = false;
    }

    private void clearRuleFields() {
        isUpdatingUI = true;
        ruleEnabledCheckBox.setSelected(false);
        matchUrlField.setText("");
        sourceComboBox.setSelectedIndex(0);
        regexField.setText("");
        updateRuleButton.setEnabled(false);
        savedRequestLabel.setText("Saved Request: None");
        refreshRequestButton.setEnabled(false);
        sendToRepeaterButton.setEnabled(false);
        editRequestButton.setEnabled(false);
        isUpdatingUI = false;
    }

    private void updateActiveRuleFromUI() {
        if (isUpdatingUI) return;
        int selectedRow = variablesTable.getSelectedRow();
        if (selectedRow >= 0) {
            String name = variableNames.get(selectedRow);
            boolean ruleEnabled = ruleEnabledCheckBox.isSelected();
            String matchUrl = matchUrlField.getText().trim();
            String source = sourceComboBox.getSelectedIndex() == 1 ? "headers" : "body";
            String regex = regexField.getText().trim();

            synchronized (lock) {
                VariableExtractionRule existingRule = rules.get(name);
                String reqBase64 = existingRule != null ? existingRule.getSavedRequestBase64() : "";
                String host = existingRule != null ? existingRule.getSavedHost() : "";
                int port = existingRule != null ? existingRule.getSavedPort() : 0;
                boolean secure = existingRule != null && existingRule.isSavedSecure();

                VariableExtractionRule rule = new VariableExtractionRule(ruleEnabled, matchUrl, source, regex,
                        reqBase64, host, port, secure);
                rules.put(name, rule);
                savePreferences();
            }
            // Update Table display
            tableModel.fireTableCellUpdated(selectedRow, 2);
        }
    }

    private void triggerSendToRepeater() {
        int selectedRow = variablesTable.getSelectedRow();
        if (selectedRow >= 0) {
            String name = variableNames.get(selectedRow);
            VariableExtractionRule rule = rules.get(name);
            if (rule != null && rule.getSavedRequestBase64() != null && !rule.getSavedRequestBase64().isEmpty()) {
                try {
                    byte[] requestBytes = Base64.getDecoder().decode(rule.getSavedRequestBase64());
                    HttpRequest savedReq = HttpRequest.httpRequest(ByteArray.byteArray(requestBytes));
                    HttpService service = HttpService.httpService(
                            rule.getSavedHost(),
                            rule.getSavedPort(),
                            rule.isSavedSecure()
                    );
                    savedReq = savedReq.withService(service);
                    
                    // Send to Repeater tool natively
                    api.repeater().sendToRepeater(savedReq, "Refresh " + name);
                } catch (Exception ex) {
                    JOptionPane.showMessageDialog(mainPanel, "Failed to send request to Repeater: " + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
                }
            }
        }
    }

    private void showEditRequestDialog() {
        int selectedRow = variablesTable.getSelectedRow();
        if (selectedRow < 0) return;
        String name = variableNames.get(selectedRow);
        VariableExtractionRule rule = rules.get(name);
        if (rule == null || rule.getSavedRequestBase64().isEmpty()) return;

        try {
            byte[] requestBytes = Base64.getDecoder().decode(rule.getSavedRequestBase64());
            String rawReqText = new String(requestBytes, StandardCharsets.UTF_8);

            JDialog editDialog = new JDialog(api.userInterface().swingUtils().suiteFrame(), "Edit Saved Request - " + name, Dialog.ModalityType.APPLICATION_MODAL);
            editDialog.setLayout(new BorderLayout(10, 10));
            editDialog.setSize(650, 500);
            editDialog.setLocationRelativeTo(api.userInterface().swingUtils().suiteFrame());

            // Header inputs panel
            JPanel headerPanel = new JPanel(new GridBagLayout());
            headerPanel.setBorder(new EmptyBorder(10, 10, 0, 10));
            GridBagConstraints hgbc = new GridBagConstraints();
            hgbc.fill = GridBagConstraints.HORIZONTAL;
            hgbc.insets = new Insets(5, 5, 5, 5);

            hgbc.gridx = 0; hgbc.gridy = 0; hgbc.weightx = 0.0;
            headerPanel.add(new JLabel("Host:"), hgbc);
            JTextField hostField = new JTextField(rule.getSavedHost());
            hgbc.gridx = 1; hgbc.weightx = 1.0;
            headerPanel.add(hostField, hgbc);

            hgbc.gridx = 2; hgbc.weightx = 0.0;
            headerPanel.add(new JLabel("Port:"), hgbc);
            JTextField portField = new JTextField(String.valueOf(rule.getSavedPort()));
            hgbc.gridx = 3; hgbc.weightx = 0.5;
            headerPanel.add(portField, hgbc);

            hgbc.gridx = 4; hgbc.weightx = 0.0;
            JCheckBox secureCheckBox = new JCheckBox("HTTPS", rule.isSavedSecure());
            headerPanel.add(secureCheckBox, hgbc);

            editDialog.add(headerPanel, BorderLayout.NORTH);

            // Editor panel
            JPanel editorPanel = new JPanel(new BorderLayout(5, 5));
            editorPanel.setBorder(new EmptyBorder(5, 10, 5, 10));
            JTextArea requestEditor = new JTextArea(rawReqText);
            requestEditor.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
            editorPanel.add(new JScrollPane(requestEditor), BorderLayout.CENTER);
            editDialog.add(editorPanel, BorderLayout.CENTER);

            // Footer buttons
            JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 10, 5));
            JButton saveButton = new JButton("Save Changes");
            JButton copyButton = new JButton("Copy to Clipboard");
            JButton cancelButton = new JButton("Cancel");

            copyButton.addActionListener(e -> {
                try {
                    StringSelection selection = new StringSelection(requestEditor.getText());
                    Toolkit.getDefaultToolkit().getSystemClipboard().setContents(selection, selection);
                    JOptionPane.showMessageDialog(editDialog, "Request copied to clipboard.", "Copied", JOptionPane.INFORMATION_MESSAGE);
                } catch (Exception ex) {
                    JOptionPane.showMessageDialog(editDialog, "Failed to copy to clipboard: " + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
                }
            });

            saveButton.addActionListener(e -> {
                String newRawReq = requestEditor.getText();
                String newHost = hostField.getText().trim();
                int newPort = 0;
                try {
                    newPort = Integer.parseInt(portField.getText().trim());
                } catch (Exception ex) {
                    JOptionPane.showMessageDialog(editDialog, "Invalid port number.", "Error", JOptionPane.ERROR_MESSAGE);
                    return;
                }
                boolean newSecure = secureCheckBox.isSelected();

                if (newHost.isEmpty()) {
                    JOptionPane.showMessageDialog(editDialog, "Host cannot be empty.", "Error", JOptionPane.ERROR_MESSAGE);
                    return;
                }

                try {
                    // Verify that it is parseable as HTTP request
                    HttpRequest.httpRequest(ByteArray.byteArray(newRawReq.getBytes(StandardCharsets.UTF_8)));
                } catch (Exception ex) {
                    JOptionPane.showMessageDialog(editDialog, "Failed to parse HTTP request. Please verify the format.", "Error", JOptionPane.ERROR_MESSAGE);
                    return;
                }

                String newReqBase64 = Base64.getEncoder().encodeToString(newRawReq.getBytes(StandardCharsets.UTF_8));
                synchronized (lock) {
                    rule.setSavedRequestBase64(newReqBase64);
                    rule.setSavedHost(newHost);
                    rule.setSavedPort(newPort);
                    rule.setSavedSecure(newSecure);
                    savePreferences();
                }
                editDialog.dispose();
                updateDetailsPanel(selectedRow);
            });

            cancelButton.addActionListener(e -> editDialog.dispose());

            buttonPanel.add(copyButton);
            buttonPanel.add(saveButton);
            buttonPanel.add(cancelButton);
            editDialog.add(buttonPanel, BorderLayout.SOUTH);

            editDialog.setVisible(true);
        } catch (Exception e) {
            api.logging().logToError("Error displaying edit request dialog: " + e.getMessage());
        }
    }

    private void triggerUpdateRuleFromResponse() {
        int selectedRow = variablesTable.getSelectedRow();
        if (selectedRow < 0) return;
        String name = variableNames.get(selectedRow);
        VariableExtractionRule rule = rules.get(name);
        if (rule == null || rule.getSavedRequestBase64() == null || rule.getSavedRequestBase64().isEmpty()) return;

        updateRuleButton.setEnabled(false);
        updateRuleButton.setText("Fetching Response...");

        // Run network operation in background thread
        new Thread(() -> {
            try {
                byte[] requestBytes = Base64.getDecoder().decode(rule.getSavedRequestBase64());
                HttpRequest savedReq = HttpRequest.httpRequest(ByteArray.byteArray(requestBytes));
                
                HttpService service = HttpService.httpService(
                        rule.getSavedHost(),
                        rule.getSavedPort(),
                        rule.isSavedSecure()
                );
                savedReq = savedReq.withService(service);

                // Replace placeholders using current variable values
                Map<String, String> variables = getVariables();

                // 1. Path
                String path = savedReq.path();
                String newPath = replacePlaceholders(path, variables);
                if (!path.equals(newPath)) {
                    savedReq = savedReq.withPath(newPath);
                }

                // 2. Headers
                List<HttpHeader> headers = savedReq.headers();
                List<HttpHeader> newHeaders = new ArrayList<>();
                boolean headersModified = false;
                for (HttpHeader header : headers) {
                    String value = header.value();
                    String newValue = replacePlaceholders(value, variables);
                    if (!value.equals(newValue)) {
                        newHeaders.add(HttpHeader.httpHeader(header.name(), newValue));
                        headersModified = true;
                    } else {
                        newHeaders.add(header);
                    }
                }
                if (headersModified) {
                    savedReq = savedReq.withRemovedHeaders(savedReq.headers()).withAddedHeaders(newHeaders);
                }

                // 3. Body
                String body = savedReq.bodyToString();
                if (body != null && !body.isEmpty()) {
                    String newBody = replacePlaceholders(body, variables);
                    if (!body.equals(newBody)) {
                        savedReq = savedReq.withBody(newBody);
                    }
                }

                // Fetch new response
                HttpRequestResponse reqResp = api.http().sendRequest(savedReq);
                if (reqResp.response() == null) {
                    SwingUtilities.invokeLater(() -> {
                        JOptionPane.showMessageDialog(mainPanel, "Failed to get response from server.", "Fetch Error", JOptionPane.ERROR_MESSAGE);
                    });
                    return;
                }

                byte[] responseBytes = reqResp.response().toByteArray().getBytes();
                String responseStr = new String(responseBytes, StandardCharsets.UTF_8);

                // Open selection dialog on EDT
                SwingUtilities.invokeLater(() -> {
                    showResponseSelectorDialog(name, rule, responseStr, selectedRow);
                });

            } catch (Exception ex) {
                api.logging().logToError("Error fetching response for extraction: " + ex.getMessage());
                SwingUtilities.invokeLater(() -> {
                    JOptionPane.showMessageDialog(mainPanel, "Error fetching response: " + ex.getMessage(), "Fetch Error", JOptionPane.ERROR_MESSAGE);
                });
            } finally {
                SwingUtilities.invokeLater(() -> {
                    updateRuleButton.setEnabled(true);
                    updateRuleButton.setText("Update Rule from Response...");
                });
            }
        }).start();
    }

    private void showResponseSelectorDialog(String varName, VariableExtractionRule rule, String responseStr, int rowIndex) {
        JDialog selectorDialog = new JDialog(api.userInterface().swingUtils().suiteFrame(), "Highlight New Token - " + varName, Dialog.ModalityType.APPLICATION_MODAL);
        selectorDialog.setLayout(new BorderLayout(10, 10));
        selectorDialog.setSize(700, 550);
        selectorDialog.setLocationRelativeTo(api.userInterface().swingUtils().suiteFrame());

        // Header instructions
        JLabel instrLabel = new JLabel("<html><body style='padding:5px;'>Highlight/select the text you want to extract from the response below. The regex will be auto-generated.</body></html>");
        selectorDialog.add(instrLabel, BorderLayout.NORTH);

        // Editor
        JTextArea responseEditor = new JTextArea(responseStr);
        responseEditor.setEditable(false);
        responseEditor.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        JScrollPane scrollPane = new JScrollPane(responseEditor);
        selectorDialog.add(scrollPane, BorderLayout.CENTER);

        // South Panel details & settings
        JPanel southPanel = new JPanel(new GridBagLayout());
        southPanel.setBorder(new EmptyBorder(10, 10, 10, 10));
        GridBagConstraints sgbc = new GridBagConstraints();
        sgbc.fill = GridBagConstraints.HORIZONTAL;
        sgbc.insets = new Insets(5, 5, 5, 5);
        sgbc.gridx = 0;

        // Row 0: Value preview
        sgbc.gridy = 0; sgbc.weightx = 0.0;
        southPanel.add(new JLabel("Selected Value:"), sgbc);
        JTextField selectedValField = new JTextField(30);
        selectedValField.setEditable(false);
        sgbc.gridx = 1; sgbc.weightx = 1.0;
        southPanel.add(selectedValField, sgbc);

        // Row 1: Regex proposed
        sgbc.gridy = 1; sgbc.gridx = 0; sgbc.weightx = 0.0;
        southPanel.add(new JLabel("Proposed Regex:"), sgbc);
        JTextField regexPropField = new JTextField(30);
        sgbc.gridx = 1; sgbc.weightx = 1.0;
        southPanel.add(regexPropField, sgbc);

        // Row 2: Extract from
        sgbc.gridy = 2; sgbc.gridx = 0; sgbc.weightx = 0.0;
        southPanel.add(new JLabel("Extract From:"), sgbc);
        JComboBox<String> extractSrcCombo = new JComboBox<>(new String[]{"Response Body", "Response Headers"});
        sgbc.gridx = 1; sgbc.weightx = 1.0;
        southPanel.add(extractSrcCombo, sgbc);

        // Add selection listener to editor
        responseEditor.addCaretListener(ce -> {
            int start = Math.min(ce.getDot(), ce.getMark());
            int end = Math.max(ce.getDot(), ce.getMark());
            if (start != end && start >= 0 && end <= responseStr.length()) {
                String selectedText = responseStr.substring(start, end);
                selectedValField.setText(selectedText);

                // Analyze source (headers vs body)
                int doubleNewline = responseStr.indexOf("\r\n\r\n");
                if (doubleNewline < 0) {
                    doubleNewline = responseStr.indexOf("\n\n");
                }

                String source = "body";
                String contextText = responseStr;
                int contextStart = start;
                int contextEnd = end;

                if (doubleNewline >= 0) {
                    if (start < doubleNewline) {
                        source = "headers";
                        contextText = responseStr.substring(0, doubleNewline);
                    } else {
                        source = "body";
                        contextText = responseStr.substring(doubleNewline + 4);
                        contextStart = Math.max(0, start - (doubleNewline + 4));
                        contextEnd = Math.max(0, end - (doubleNewline + 4));
                    }
                }

                String proposedRegex = generateProposedRegex(contextText, contextStart, contextEnd);
                regexPropField.setText(proposedRegex);
                extractSrcCombo.setSelectedIndex("headers".equalsIgnoreCase(source) ? 1 : 0);
            }
        });

        // Action Buttons panel
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 10, 5));
        JButton saveBtn = new JButton("Save Extraction Rule");
        JButton cancelBtn = new JButton("Cancel");

        saveBtn.addActionListener(al -> {
            String finalRegex = regexPropField.getText().trim();
            if (finalRegex.isEmpty()) {
                JOptionPane.showMessageDialog(selectorDialog, "Please select some text to generate a regex.", "Error", JOptionPane.ERROR_MESSAGE);
                return;
            }
            String chosenSource = extractSrcCombo.getSelectedIndex() == 1 ? "headers" : "body";

            synchronized (lock) {
                rule.setRegex(finalRegex);
                rule.setSource(chosenSource);
                rule.setEnabled(true);
                savePreferences();
            }
            selectorDialog.dispose();
            updateDetailsPanel(rowIndex);
            // Flash a success notification
            JOptionPane.showMessageDialog(mainPanel, "Extraction rule updated successfully for variable: " + varName, "Rule Updated", JOptionPane.INFORMATION_MESSAGE);
        });

        cancelBtn.addActionListener(al -> selectorDialog.dispose());
        buttonPanel.add(saveBtn);
        buttonPanel.add(cancelBtn);

        // Put panels together
        JPanel wrapperPanel = new JPanel(new BorderLayout(5, 5));
        wrapperPanel.add(southPanel, BorderLayout.CENTER);
        wrapperPanel.add(buttonPanel, BorderLayout.SOUTH);
        selectorDialog.add(wrapperPanel, BorderLayout.SOUTH);

        selectorDialog.setVisible(true);
    }

    private String generateProposedRegex(String fullText, int start, int end) {
        if (fullText == null || start < 0 || end > fullText.length() || start >= end) {
            return "";
        }

        // Context search limits
        int precedingLimit = Math.max(0, start - 50);
        String preceding = fullText.substring(precedingLimit, start);

        int succeedingLimit = Math.min(fullText.length(), end + 30);
        String succeeding = fullText.substring(end, succeedingLimit);

        // 1. JSON key match: "key" : "value"
        java.util.regex.Pattern jsonPattern = java.util.regex.Pattern.compile("\"([a-zA-Z0-9_\\-]+)\"\\s*:\\s*\"$");
        java.util.regex.Matcher jsonMatcher = jsonPattern.matcher(preceding);
        if (jsonMatcher.find()) {
            String key = jsonMatcher.group(1);
            return "\"" + key + "\"\\s*:\\s*\"([^\"]+)\"";
        }

        // 2. Query/Form parameter match: key=value
        java.util.regex.Pattern paramPattern = java.util.regex.Pattern.compile("(?:[?&\\s]|^)([a-zA-Z0-9_\\-]+)=$");
        java.util.regex.Matcher paramMatcher = paramPattern.matcher(preceding);
        if (paramMatcher.find()) {
            String key = paramMatcher.group(1);
            return key + "=([^&\\s;]+)";
        }

        // 3. XML tag match: <tag>value</tag>
        java.util.regex.Pattern xmlPattern = java.util.regex.Pattern.compile("<([a-zA-Z0-9_\\-]+)>$");
        java.util.regex.Matcher xmlMatcher = xmlPattern.matcher(preceding);
        if (xmlMatcher.find()) {
            String tag = xmlMatcher.group(1);
            return "<" + tag + ">(.*?)</" + tag + ">";
        }

        // 4. Default fallback: escape surrounding characters on the same line
        int lastNewline = preceding.lastIndexOf('\n');
        if (lastNewline >= 0) {
            preceding = preceding.substring(lastNewline + 1);
        }
        int firstNewline = succeeding.indexOf('\n');
        if (firstNewline >= 0) {
            succeeding = succeeding.substring(0, firstNewline);
        }

        String prefix = preceding.substring(Math.max(0, preceding.length() - 10));
        String suffix = succeeding.substring(0, Math.min(succeeding.length(), 5));

        return java.util.regex.Pattern.quote(prefix) + "(.*?)" + java.util.regex.Pattern.quote(suffix);
    }

    private void triggerBackgroundRefresh() {
        int selectedRow = variablesTable.getSelectedRow();
        if (selectedRow >= 0) {
            String name = variableNames.get(selectedRow);
            VariableExtractionRule rule = rules.get(name);
            if (rule != null && rule.getSavedRequestBase64() != null && !rule.getSavedRequestBase64().isEmpty()) {
                refreshRequestButton.setEnabled(false);
                refreshRequestButton.setText("Refreshing...");
                
                // Run background thread to comply with BApp responsiveness guidelines
                new Thread(() -> {
                    try {
                        refreshVariableSynchronously(name, rule);
                        SwingUtilities.invokeLater(() -> {
                            String extractedValue = values.getOrDefault(name, "");
                            JOptionPane.showMessageDialog(mainPanel, 
                                    "Variable '" + name + "' refreshed successfully to:\n" + extractedValue, 
                                    "Refresh Success", JOptionPane.INFORMATION_MESSAGE);
                        });
                    } catch (Exception ex) {
                        api.logging().logToError("Error refreshing variable '" + name + "': " + ex.getMessage());
                        SwingUtilities.invokeLater(() -> {
                            JOptionPane.showMessageDialog(mainPanel, "Error during refresh: " + ex.getMessage(), "Refresh Error", JOptionPane.ERROR_MESSAGE);
                        });
                    } finally {
                        SwingUtilities.invokeLater(() -> {
                            refreshRequestButton.setEnabled(true);
                            refreshRequestButton.setText("Refresh Variable");
                        });
                    }
                }).start();
            }
        }
    }

    // Synchronous execution (can block the calling thread)
    public void refreshVariableSynchronously(String name, VariableExtractionRule rule) throws Exception {
        if (rule == null || rule.getSavedRequestBase64() == null || rule.getSavedRequestBase64().isEmpty()) {
            return;
        }
        
        byte[] requestBytes = Base64.getDecoder().decode(rule.getSavedRequestBase64());
        HttpRequest savedReq = HttpRequest.httpRequest(ByteArray.byteArray(requestBytes));
        
        HttpService service = HttpService.httpService(
                rule.getSavedHost(),
                rule.getSavedPort(),
                rule.isSavedSecure()
        );
        savedReq = savedReq.withService(service);

        // Replace placeholders in the refresh request template using current variables!
        Map<String, String> variables = getVariables();

        // 1. Path replacement
        String path = savedReq.path();
        String newPath = replacePlaceholders(path, variables);
        if (!path.equals(newPath)) {
            savedReq = savedReq.withPath(newPath);
        }

        // 2. Headers replacement
        List<HttpHeader> headers = savedReq.headers();
        List<HttpHeader> newHeaders = new ArrayList<>();
        boolean headersModified = false;
        for (HttpHeader header : headers) {
            String value = header.value();
            String newValue = replacePlaceholders(value, variables);
            if (!value.equals(newValue)) {
                newHeaders.add(HttpHeader.httpHeader(header.name(), newValue));
                headersModified = true;
            } else {
                newHeaders.add(header);
            }
        }
        if (headersModified) {
            savedReq = savedReq.withRemovedHeaders(savedReq.headers()).withAddedHeaders(newHeaders);
        }

        // 3. Body replacement
        String body = savedReq.bodyToString();
        if (body != null && !body.isEmpty()) {
            String newBody = replacePlaceholders(body, variables);
            if (!body.equals(newBody)) {
                savedReq = savedReq.withBody(newBody);
            }
        }

        // Send request programmatically via Burp HTTP engine
        HttpRequestResponse reqResp = api.http().sendRequest(savedReq);

        if (reqResp.response() != null) {
            String sourceContent = "";
            if ("headers".equalsIgnoreCase(rule.getSource())) {
                StringBuilder sb = new StringBuilder();
                for (HttpHeader header : reqResp.response().headers()) {
                    sb.append(header.name()).append(": ").append(header.value()).append("\r\n");
                }
                sourceContent = sb.toString();
            } else {
                sourceContent = reqResp.response().bodyToString();
            }

            if (sourceContent != null && !sourceContent.isEmpty()) {
                java.util.regex.Pattern regexPattern = java.util.regex.Pattern.compile(rule.getRegex(), java.util.regex.Pattern.DOTALL);
                java.util.regex.Matcher matcher = regexPattern.matcher(sourceContent);
                if (matcher.find() && matcher.groupCount() >= 1) {
                    String extractedValue = matcher.group(1);
                    if (extractedValue != null) {
                        updateVariableValue(name, extractedValue);
                    }
                } else {
                    throw new Exception("Regex pattern did not match response.");
                }
            } else {
                throw new Exception("Server response was empty.");
            }
        } else {
            throw new Exception("No response received from target.");
        }
    }

    private String replacePlaceholders(String text, Map<String, String> variables) {
        if (text == null || text.isEmpty()) {
            return text;
        }
        String result = text;
        for (Map.Entry<String, String> entry : variables.entrySet()) {
            String placeholder = "{{" + entry.getKey() + "}}";
            if (result.contains(placeholder)) {
                result = result.replace(placeholder, entry.getValue());
            }
        }
        return result;
    }

    public void savePreferences() {
        synchronized (lock) {
            try {
                // Save variable values
                StringBuilder valSb = new StringBuilder();
                for (String name : variableNames) {
                    String val = values.getOrDefault(name, "");
                    valSb.append(URLEncoder.encode(name, StandardCharsets.UTF_8.name()))
                         .append("=")
                         .append(URLEncoder.encode(val, StandardCharsets.UTF_8.name()))
                         .append("&");
                }
                api.persistence().preferences().setString("repeater_variables_values", valSb.toString());

                // Save variable rules
                StringBuilder ruleSb = new StringBuilder();
                for (String name : variableNames) {
                    VariableExtractionRule rule = rules.get(name);
                    if (rule != null) {
                        ruleSb.append(URLEncoder.encode(name, StandardCharsets.UTF_8.name()))
                              .append("=")
                              .append(URLEncoder.encode(rule.serialize(), StandardCharsets.UTF_8.name()))
                              .append("&");
                    }
                }
                api.persistence().preferences().setString("repeater_variables_rules", ruleSb.toString());

                // Save global toggles
                api.persistence().preferences().setString("repeater_variables_replacement_master_enabled", String.valueOf(replacementMasterEnabled));
                api.persistence().preferences().setString("repeater_variables_replacement_enabled", String.valueOf(replacementEnabled));
                api.persistence().preferences().setString("repeater_variables_replacement_intruder_enabled", String.valueOf(replacementIntruderEnabled));
                api.persistence().preferences().setString("repeater_variables_replacement_scanner_enabled", String.valueOf(replacementScannerEnabled));
                api.persistence().preferences().setString("repeater_variables_replacement_proxy_enabled", String.valueOf(replacementProxyEnabled));
                api.persistence().preferences().setString("repeater_variables_extraction_enabled", String.valueOf(extractionEnabled));
                api.persistence().preferences().setString("repeater_variables_refresh_status_codes", refreshStatusCodes);
            } catch (Exception e) {
                api.logging().logToError("Failed to save variables preferences: " + e.getMessage());
            }
        }
    }

    public void loadPreferences() {
        synchronized (lock) {
            try {
                variableNames.clear();
                values.clear();
                rules.clear();

                String valPref = api.persistence().preferences().getString("repeater_variables_values");
                if (valPref != null && !valPref.isEmpty()) {
                    String[] pairs = valPref.split("&");
                    for (String pair : pairs) {
                        if (pair.isEmpty()) continue;
                        int idx = pair.indexOf("=");
                        if (idx > 0) {
                            String name = URLDecoder.decode(pair.substring(0, idx), StandardCharsets.UTF_8.name());
                            String val = URLDecoder.decode(pair.substring(idx + 1), StandardCharsets.UTF_8.name());
                            variableNames.add(name);
                            values.put(name, val);
                        }
                    }
                }

                String rulePref = api.persistence().preferences().getString("repeater_variables_rules");
                if (rulePref != null && !rulePref.isEmpty()) {
                    String[] pairs = rulePref.split("&");
                    for (String pair : pairs) {
                        if (pair.isEmpty()) continue;
                        int idx = pair.indexOf("=");
                        if (idx > 0) {
                            String name = URLDecoder.decode(pair.substring(0, idx), StandardCharsets.UTF_8.name());
                            String ruleData = URLDecoder.decode(pair.substring(idx + 1), StandardCharsets.UTF_8.name());
                            rules.put(name, VariableExtractionRule.deserialize(ruleData));
                        }
                    }
                }

                // Default empty rules for variables without them
                for (String name : variableNames) {
                    if (!rules.containsKey(name)) {
                        rules.put(name, new VariableExtractionRule());
                    }
                }

                String replaceMasterPref = api.persistence().preferences().getString("repeater_variables_replacement_master_enabled");
                if (replaceMasterPref != null) {
                    replacementMasterEnabled = Boolean.parseBoolean(replaceMasterPref);
                }

                String replaceEnabledPref = api.persistence().preferences().getString("repeater_variables_replacement_enabled");
                if (replaceEnabledPref != null) {
                    replacementEnabled = Boolean.parseBoolean(replaceEnabledPref);
                }
                
                String replaceIntruderPref = api.persistence().preferences().getString("repeater_variables_replacement_intruder_enabled");
                if (replaceIntruderPref != null) {
                    replacementIntruderEnabled = Boolean.parseBoolean(replaceIntruderPref);
                }

                String replaceScannerPref = api.persistence().preferences().getString("repeater_variables_replacement_scanner_enabled");
                if (replaceScannerPref != null) {
                    replacementScannerEnabled = Boolean.parseBoolean(replaceScannerPref);
                }

                String replaceProxyPref = api.persistence().preferences().getString("repeater_variables_replacement_proxy_enabled");
                if (replaceProxyPref != null) {
                    replacementProxyEnabled = Boolean.parseBoolean(replaceProxyPref);
                }

                String extractEnabledPref = api.persistence().preferences().getString("repeater_variables_extraction_enabled");
                if (extractEnabledPref != null) {
                    extractionEnabled = Boolean.parseBoolean(extractEnabledPref);
                }
                
                String codesPref = api.persistence().preferences().getString("repeater_variables_refresh_status_codes");
                if (codesPref != null) {
                    refreshStatusCodes = codesPref;
                }
            } catch (Exception e) {
                api.logging().logToError("Failed to load variables preferences: " + e.getMessage());
            }
        }
    }

    // --- TABLE MODEL CLASS ---
    private class VariablesTableModel extends AbstractTableModel {
        private final String[] columns = {"Variable Name", "Current Value", "Auto Extract?"};

        @Override
        public int getRowCount() {
            synchronized (lock) {
                return variableNames.size();
            }
        }

        @Override
        public int getColumnCount() {
            return columns.length;
        }

        @Override
        public String getColumnName(int column) {
            return columns[column];
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            synchronized (lock) {
                if (rowIndex >= variableNames.size()) return null;
                String name = variableNames.get(rowIndex);
                switch (columnIndex) {
                    case 0:
                        return name;
                    case 1:
                        String val = values.getOrDefault(name, "");
                        return val.length() > 50 ? val.substring(0, 47) + "..." : val;
                    case 2:
                        VariableExtractionRule rule = rules.get(name);
                        return (rule != null && rule.isEnabled()) ? "Yes" : "No";
                }
            }
            return null;
        }

        @Override
        public boolean isCellEditable(int rowIndex, int columnIndex) {
            return columnIndex == 0;
        }

        @Override
        public void setValueAt(Object aValue, int rowIndex, int columnIndex) {
            if (columnIndex == 0 && aValue != null) {
                String newName = aValue.toString().trim();
                if (newName.isEmpty()) return;
                
                synchronized (lock) {
                    String oldName = variableNames.get(rowIndex);
                    if (oldName.equals(newName)) return;
                    if (variableNames.contains(newName)) {
                        JOptionPane.showMessageDialog(mainPanel, "Variable name already exists!", "Error", JOptionPane.ERROR_MESSAGE);
                        return;
                    }
                    
                    variableNames.set(rowIndex, newName);
                    values.put(newName, values.remove(oldName));
                    rules.put(newName, rules.remove(oldName));
                    savePreferences();
                }
                fireTableRowsUpdated(rowIndex, rowIndex);
            }
        }
    }

    // --- HELPERS ---
    private interface SimpleCallback {
        void run();
    }

    private static class SimpleDocumentListener implements DocumentListener {
        private final SimpleCallback callback;

        public SimpleDocumentListener(SimpleCallback callback) {
            this.callback = callback;
        }

        @Override
        public void insertUpdate(DocumentEvent e) { callback.run(); }

        @Override
        public void removeUpdate(DocumentEvent e) { callback.run(); }

        @Override
        public void changedUpdate(DocumentEvent e) { callback.run(); }
    }
}
