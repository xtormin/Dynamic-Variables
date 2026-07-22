package burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.Selection;
import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.ui.editor.RawEditor;
import burp.api.montoya.ui.editor.extension.EditorCreationContext;
import burp.api.montoya.ui.editor.extension.EditorMode;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpRequestEditor;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class VariableRequestEditor implements ExtensionProvidedHttpRequestEditor {
    private final MontoyaApi api;
    private final VariableManager variableManager;
    private final EditorCreationContext creationContext;
    private final RawEditor nativeEditor;

    private JPanel mainPanel;
    private JList<String> varList;
    private DefaultListModel<String> listModel;
    private JSplitPane splitPane;
    private HttpRequestResponse currentReqResp;
    private final Map<String, String> displayToVariable = new HashMap<>();
    private final Set<String> collapsedFolders = new HashSet<>();
    private String filter = "";

    public VariableRequestEditor(MontoyaApi api, VariableManager variableManager, EditorCreationContext creationContext) {
        this.api = api;
        this.variableManager = variableManager;
        this.creationContext = creationContext;

        // Initialize native Burp raw editor to avoid duplicated inner tabs
        if (creationContext.editorMode() == EditorMode.READ_ONLY) {
            this.nativeEditor = api.userInterface().createRawEditor(EditorOptions.READ_ONLY);
        } else {
            this.nativeEditor = api.userInterface().createRawEditor();
        }

        createUI();
    }

    private void createUI() {
        mainPanel = new JPanel(new BorderLayout());

        // Left Sidebar: Variables list panel
        JPanel sidebarPanel = new JPanel(new BorderLayout(5, 5));
        sidebarPanel.setBorder(new EmptyBorder(5, 5, 5, 5));
        sidebarPanel.setMinimumSize(new Dimension(130, 100));
        sidebarPanel.setPreferredSize(new Dimension(150, 200));

        // Header label
        JLabel headerLabel = new JLabel("Double-click a variable to insert:");
        headerLabel.setFont(new Font(headerLabel.getFont().getName(), Font.BOLD, 11));
        JTextField searchField = new JTextField();
        searchField.putClientProperty("JTextField.placeholderText", "Search variables");
        searchField.getDocument().addDocumentListener(new DocumentListener() {
            private void update() {
                filter = searchField.getText().trim().toLowerCase(java.util.Locale.ROOT);
                refreshVariableList();
            }
            @Override public void insertUpdate(DocumentEvent e) { update(); }
            @Override public void removeUpdate(DocumentEvent e) { update(); }
            @Override public void changedUpdate(DocumentEvent e) { update(); }
        });
        JPanel sidebarHeader = new JPanel(new BorderLayout(3, 3));
        sidebarHeader.add(headerLabel, BorderLayout.NORTH);
        sidebarHeader.add(searchField, BorderLayout.SOUTH);
        sidebarPanel.add(sidebarHeader, BorderLayout.NORTH);

        // Variables List
        listModel = new DefaultListModel<>();
        varList = new JList<>(listModel);
        varList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        varList.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));

        // Custom cell renderer to show variable value as tooltip
        varList.setCellRenderer(new DefaultListCellRenderer() {
            @Override
            public Component getListCellRendererComponent(JList<?> list, Object value, int index, boolean isSelected, boolean cellHasFocus) {
                Component c = super.getListCellRendererComponent(list, value, index, isSelected, cellHasFocus);
                if (value != null) {
                    String varName = displayToVariable.get(value.toString());
                    if (varName == null) {
                        setFont(getFont().deriveFont(Font.BOLD));
                        setToolTipText("Double-click to expand or collapse");
                        return c;
                    }
                    String varValue = variableManager.getVariables().get(varName);
                    if (varValue != null) {
                        // Truncate long values for tooltip
                        if (varValue.length() > 200) {
                            varValue = varValue.substring(0, 200) + "...";
                        }
                        // Use basic HTML to wrap text if it's long
                        setToolTipText("<html><p style='width: 300px; word-wrap: break-word;'>" + 
                            varValue.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;") + 
                            "</p></html>");
                    } else {
                        setToolTipText("No value");
                    }
                }
                return c;
            }
        });

        // Double-click selection action listener
        varList.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2 && !varList.isSelectionEmpty()) {
                    String display = varList.getSelectedValue();
                    String selectedVar = displayToVariable.get(display);
                    if (selectedVar != null) insertPlaceholder(selectedVar);
                    else toggleFolder(display);
                }
            }
        });

        sidebarPanel.add(new JScrollPane(varList), BorderLayout.CENTER);

        // Sidebar Bottom Buttons Panel
        JPanel sidebarButtonsPanel = new JPanel(new GridLayout(1, 2, 4, 4));
        JButton insertButton = new JButton("Insert");
        insertButton.setFont(new Font(insertButton.getFont().getName(), Font.PLAIN, 10));
        insertButton.addActionListener(e -> {
            if (!varList.isSelectionEmpty()) {
                String selected = displayToVariable.get(varList.getSelectedValue());
                if (selected != null) insertPlaceholder(selected);
            }
        });

        JButton refreshButton = new JButton("Refresh");
        refreshButton.setFont(new Font(refreshButton.getFont().getName(), Font.PLAIN, 10));
        refreshButton.addActionListener(e -> refreshVariableList());

        sidebarButtonsPanel.add(insertButton);
        sidebarButtonsPanel.add(refreshButton);
        sidebarPanel.add(sidebarButtonsPanel, BorderLayout.SOUTH);

        // Split Pane wrapping the sidebar on the left and native editor on the right
        splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        splitPane.setLeftComponent(sidebarPanel);
        splitPane.setRightComponent(nativeEditor.uiComponent());
        splitPane.setDividerLocation(150);

        mainPanel.add(splitPane, BorderLayout.CENTER);
        
        // Load initial list contents
        refreshVariableList();
    }

    private void refreshVariableList() {
        listModel.clear();
        displayToVariable.clear();
        List<String> names = variableManager.getVariableNames();
        List<String> folders = new ArrayList<>();
        folders.add("");
        folders.addAll(variableManager.getFolderNames());
        for (String folder : folders) {
            List<String> matches = names.stream().filter(name -> variableManager.getFolderNameForVariable(name).equals(folder))
                    .filter(name -> filter.isEmpty() || name.toLowerCase(java.util.Locale.ROOT).contains(filter)
                            || folder.toLowerCase(java.util.Locale.ROOT).contains(filter)).toList();
            if (matches.isEmpty() && !filter.isEmpty()) continue;
            String label = (collapsedFolders.contains(folder) && filter.isEmpty() ? "▸ " : "▾ ") + "📁 "
                    + (folder.isEmpty() ? "Ungrouped" : folder) + " (" + matches.size() + ")";
            listModel.addElement(label);
            if (!collapsedFolders.contains(folder) || !filter.isEmpty()) {
                for (String name : matches) {
                    String display = "    " + name;
                    listModel.addElement(display);
                    displayToVariable.put(display, name);
                }
            }
        }
    }

    private void toggleFolder(String display) {
        if (display == null) return;
        int marker = display.indexOf("📁 ");
        int count = display.lastIndexOf(" (");
        if (marker < 0 || count < marker) return;
        String folder = display.substring(marker + 3, count);
        if ("Ungrouped".equals(folder)) folder = "";
        if (!collapsedFolders.add(folder)) collapsedFolders.remove(folder);
        refreshVariableList();
    }

    private boolean isLocallyModified = false;

    private void insertPlaceholder(String varName) {
        if (creationContext.editorMode() == EditorMode.READ_ONLY) {
            return;
        }

        ByteArray currentReqBytes = nativeEditor.getContents();
        if (currentReqBytes != null) {
            byte[] requestBytes = currentReqBytes.getBytes();
            String reqStr = new String(requestBytes, StandardCharsets.UTF_8);
            
            Selection selection = nativeEditor.selection().orElse(null);
            int caret = nativeEditor.caretPosition();
            
            String placeholder = "{{" + varName + "}}";
            String newReqStr;
            int newCaret;

            if (selection != null && selection.offsets().startIndexInclusive() < selection.offsets().endIndexExclusive()) {
                int start = selection.offsets().startIndexInclusive();
                int end = selection.offsets().endIndexExclusive();
                String prefix = reqStr.substring(0, start);
                String suffix = reqStr.substring(end);
                newReqStr = prefix + placeholder + suffix;
                newCaret = start + placeholder.length();
            } else if (caret >= 0 && caret <= reqStr.length()) {
                String prefix = reqStr.substring(0, caret);
                String suffix = reqStr.substring(caret);
                newReqStr = prefix + placeholder + suffix;
                newCaret = caret + placeholder.length();
            } else {
                return;
            }

            nativeEditor.setContents(ByteArray.byteArray(newReqStr.getBytes(StandardCharsets.UTF_8)));
            this.isLocallyModified = true;

            if (newCaret <= newReqStr.length()) {
                nativeEditor.setCaretPosition(newCaret);
            }
            
            // Grab focus back to the editor for continuous editing
            nativeEditor.uiComponent().requestFocusInWindow();
        }
    }

    @Override
    public HttpRequest getRequest() {
        if (currentReqResp != null && currentReqResp.request() != null && currentReqResp.request().httpService() != null) {
            return HttpRequest.httpRequest(currentReqResp.request().httpService(), nativeEditor.getContents());
        }
        return HttpRequest.httpRequest(nativeEditor.getContents());
    }

    @Override
    public void setRequestResponse(HttpRequestResponse requestResponse) {
        this.currentReqResp = requestResponse;
        this.isLocallyModified = false;
        if (requestResponse != null && requestResponse.request() != null) {
            nativeEditor.setContents(requestResponse.request().toByteArray());
        } else {
            nativeEditor.setContents(ByteArray.byteArray(new byte[0]));
        }
        refreshVariableList();
    }

    @Override
    public boolean isEnabledFor(HttpRequestResponse requestResponse) {
        // Only display if the context isn't an extension creating its own editor (avoids infinite loops if another extension embeds editors)
        if (creationContext.toolSource().toolType() == burp.api.montoya.core.ToolType.EXTENSIONS) {
            return false;
        }
        return true;
    }

    @Override
    public String caption() {
        return "Dynamic Variables";
    }

    @Override
    public Component uiComponent() {
        return mainPanel;
    }

    @Override
    public Selection selectedData() {
        return nativeEditor.selection().orElse(null);
    }

    @Override
    public boolean isModified() {
        return isLocallyModified || nativeEditor.isModified();
    }
}
