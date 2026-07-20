package burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Range;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Collections;
import java.util.List;

public class VariableContextMenuProvider implements ContextMenuItemsProvider {
    private final MontoyaApi api;
    private final VariableManager variableManager;

    public VariableContextMenuProvider(MontoyaApi api, VariableManager variableManager) {
        this.api = api;
        this.variableManager = variableManager;
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        if (event.messageEditorRequestResponse().isEmpty()) {
            return Collections.emptyList();
        }

        MessageEditorHttpRequestResponse reqResp = event.messageEditorRequestResponse().get();
        if (reqResp.selectionOffsets().isEmpty()) {
            return Collections.emptyList();
        }

        // Only show if selection context is RESPONSE
        if (reqResp.selectionContext() != MessageEditorHttpRequestResponse.SelectionContext.RESPONSE) {
            return Collections.emptyList();
        }

        JMenuItem menuItem = new JMenuItem("Assign to Variable...");
        menuItem.addActionListener(e -> showConfigDialog(event));

        return List.of(menuItem);
    }

    private void showConfigDialog(ContextMenuEvent event) {
        MessageEditorHttpRequestResponse reqResp = event.messageEditorRequestResponse().get();
        Range range = reqResp.selectionOffsets().get();
        int start = range.startIndexInclusive();
        int end = range.endIndexExclusive();

        HttpRequestResponse requestResponse = reqResp.requestResponse();
        byte[] responseBytes = requestResponse.response().toByteArray().getBytes();
        String responseStr = new String(responseBytes, StandardCharsets.UTF_8);
        String path = requestResponse.request().path();

        // Slice selected text
        if (start < 0 || end > responseStr.length() || start >= end) {
            Frame suiteFrame = api.userInterface().swingUtils().suiteFrame();
            JOptionPane.showMessageDialog(suiteFrame, "Invalid selection range.", "Error", JOptionPane.ERROR_MESSAGE);
            return;
        }
        String selectedText = responseStr.substring(start, end);

        // Determine if selection is in headers or body
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

        // Generate proposed regex
        String proposedRegex = generateProposedRegex(contextText, contextStart, contextEnd);

        // Build the Swing dialog
        Frame suiteFrame = api.userInterface().swingUtils().suiteFrame();
        JDialog dialog = new JDialog(suiteFrame, "Assign to Variable", Dialog.ModalityType.APPLICATION_MODAL);
        dialog.setLayout(new BorderLayout(10, 10));
        dialog.setSize(500, 420); // slightly taller to accommodate the new checkbox
        dialog.setLocationRelativeTo(suiteFrame);

        JPanel panel = new JPanel(new GridBagLayout());
        panel.setBorder(new EmptyBorder(10, 10, 10, 10));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.gridx = 0;

        // Row 0: Variable Name (Editable ComboBox)
        gbc.gridy = 0;
        gbc.weightx = 0.0;
        panel.add(new JLabel("Variable Name:"), gbc);

        List<String> names = variableManager.getVariableNames();
        JComboBox<String> nameComboBox = new JComboBox<>(names.toArray(new String[0]));
        nameComboBox.setEditable(true);
        if (!names.isEmpty()) {
            nameComboBox.setSelectedIndex(0);
        }
        gbc.gridx = 1;
        gbc.weightx = 1.0;
        panel.add(nameComboBox, gbc);

        // Row 1: Selected Value (Read-only scrollpane)
        gbc.gridy = 1;
        gbc.gridx = 0;
        gbc.weightx = 0.0;
        panel.add(new JLabel("Selected Value:"), gbc);

        JTextArea valuePreview = new JTextArea(3, 20);
        valuePreview.setText(selectedText);
        valuePreview.setEditable(false);
        valuePreview.setLineWrap(true);
        valuePreview.setWrapStyleWord(true);
        valuePreview.setBackground(panel.getBackground());
        gbc.gridx = 1;
        gbc.weightx = 1.0;
        panel.add(new JScrollPane(valuePreview), gbc);

        // Row 2: Match URL/Path
        gbc.gridy = 2;
        gbc.gridx = 0;
        gbc.weightx = 0.0;
        panel.add(new JLabel("Match URL/Path (Regex):"), gbc);

        JTextField pathField = new JTextField(path);
        gbc.gridx = 1;
        gbc.weightx = 1.0;
        panel.add(pathField, gbc);

        // Row 3: Extract From
        gbc.gridy = 3;
        gbc.gridx = 0;
        gbc.weightx = 0.0;
        panel.add(new JLabel("Extract From:"), gbc);

        JComboBox<String> sourceComboBox = new JComboBox<>(new String[]{"Response Body", "Response Headers"});
        if ("headers".equals(source)) {
            sourceComboBox.setSelectedIndex(1);
        } else {
            sourceComboBox.setSelectedIndex(0);
        }
        gbc.gridx = 1;
        gbc.weightx = 1.0;
        panel.add(sourceComboBox, gbc);

        // Row 4: Regex Pattern
        gbc.gridy = 4;
        gbc.gridx = 0;
        gbc.weightx = 0.0;
        panel.add(new JLabel("Regex Pattern (1 group):"), gbc);

        JTextField regexField = new JTextField(proposedRegex);
        gbc.gridx = 1;
        gbc.weightx = 1.0;
        panel.add(regexField, gbc);

        // Row 5: Save Request checkbox
        gbc.gridy = 5;
        gbc.gridx = 0;
        gbc.gridwidth = 2;
        JCheckBox saveRequestCheckBox = new JCheckBox("Save this request to refresh token in the future", true);
        panel.add(saveRequestCheckBox, gbc);

        gbc.gridwidth = 1;

        // Row 6: Action Buttons
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 10, 5));
        JButton saveButton = new JButton("Save Rule");
        JButton cancelButton = new JButton("Cancel");

        saveButton.addActionListener(al -> {
            Object selectedItem = nameComboBox.getSelectedItem();
            if (selectedItem == null || selectedItem.toString().trim().isEmpty()) {
                JOptionPane.showMessageDialog(dialog, "Please select or type a variable name.", "Error", JOptionPane.ERROR_MESSAGE);
                return;
            }
            String varName = selectedItem.toString().trim();
            String pathFilter = pathField.getText().trim();
            String chosenSource = sourceComboBox.getSelectedIndex() == 1 ? "headers" : "body";
            String regexPattern = regexField.getText().trim();

            String reqBase64 = "";
            String host = "";
            int port = 0;
            boolean secure = false;

            if (saveRequestCheckBox.isSelected()) {
                byte[] requestBytes = requestResponse.request().toByteArray().getBytes();
                reqBase64 = Base64.getEncoder().encodeToString(requestBytes);
                host = requestResponse.request().httpService().host();
                port = requestResponse.request().httpService().port();
                secure = requestResponse.request().httpService().secure();
            }

            // Save variables & rules
            variableManager.addOrUpdateExtractionRule(
                    varName, 
                    selectedText, 
                    true, 
                    pathFilter, 
                    chosenSource, 
                    regexPattern,
                    reqBase64,
                    host,
                    port,
                    secure
            );
            dialog.dispose();
        });

        cancelButton.addActionListener(al -> dialog.dispose());

        buttonPanel.add(saveButton);
        buttonPanel.add(cancelButton);

        dialog.add(panel, BorderLayout.CENTER);
        dialog.add(buttonPanel, BorderLayout.SOUTH);
        dialog.setVisible(true);
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
}
