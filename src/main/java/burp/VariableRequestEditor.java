package burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.Selection;
import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.extension.EditorCreationContext;
import burp.api.montoya.ui.editor.extension.EditorMode;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpRequestEditor;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.nio.charset.StandardCharsets;
import java.util.List;

public class VariableRequestEditor implements ExtensionProvidedHttpRequestEditor {
    private final MontoyaApi api;
    private final VariableManager variableManager;
    private final EditorCreationContext creationContext;
    private final HttpRequestEditor nativeEditor;

    private JPanel mainPanel;
    private JList<String> varList;
    private DefaultListModel<String> listModel;
    private JSplitPane splitPane;
    private HttpRequestResponse currentReqResp;

    public VariableRequestEditor(MontoyaApi api, VariableManager variableManager, EditorCreationContext creationContext) {
        this.api = api;
        this.variableManager = variableManager;
        this.creationContext = creationContext;

        // Initialize native Burp request editor based on read-only constraints
        if (creationContext.editorMode() == EditorMode.READ_ONLY) {
            this.nativeEditor = api.userInterface().createHttpRequestEditor(EditorOptions.READ_ONLY);
        } else {
            this.nativeEditor = api.userInterface().createHttpRequestEditor();
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
        JLabel headerLabel = new JLabel("Double-click to insert:");
        headerLabel.setFont(new Font(headerLabel.getFont().getName(), Font.BOLD, 11));
        sidebarPanel.add(headerLabel, BorderLayout.NORTH);

        // Variables List
        listModel = new DefaultListModel<>();
        varList = new JList<>(listModel);
        varList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        varList.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));

        // Double-click selection action listener
        varList.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2 && !varList.isSelectionEmpty()) {
                    String selectedVar = varList.getSelectedValue();
                    insertPlaceholder(selectedVar);
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
                insertPlaceholder(varList.getSelectedValue());
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
        List<String> names = variableManager.getVariableNames();
        for (String name : names) {
            listModel.addElement(name);
        }
    }

    private void insertPlaceholder(String varName) {
        if (creationContext.editorMode() == EditorMode.READ_ONLY) {
            return;
        }

        HttpRequest currentReq = nativeEditor.getRequest();
        if (currentReq != null) {
            byte[] requestBytes = currentReq.toByteArray().getBytes();
            String reqStr = new String(requestBytes, StandardCharsets.UTF_8);
            int caret = nativeEditor.caretPosition();

            if (caret >= 0 && caret <= reqStr.length()) {
                String placeholder = "{{" + varName + "}}";
                String prefix = reqStr.substring(0, caret);
                String suffix = reqStr.substring(caret);
                String newReqStr = prefix + placeholder + suffix;

                HttpRequest newReq = HttpRequest.httpRequest(currentReq.httpService(), newReqStr);
                nativeEditor.setRequest(newReq);

                // Set caret position right after the newly inserted placeholder template
                int newCaret = caret + placeholder.length();
                if (newCaret <= newReqStr.length()) {
                    nativeEditor.setCaretPosition(newCaret);
                }
                
                // Grab focus back to the editor for continuous editing
                nativeEditor.uiComponent().requestFocusInWindow();
            }
        }
    }

    @Override
    public HttpRequest getRequest() {
        return nativeEditor.getRequest();
    }

    @Override
    public void setRequestResponse(HttpRequestResponse requestResponse) {
        this.currentReqResp = requestResponse;
        if (requestResponse != null && requestResponse.request() != null) {
            nativeEditor.setRequest(requestResponse.request());
        }
        refreshVariableList();
    }

    @Override
    public boolean isEnabledFor(HttpRequestResponse requestResponse) {
        // Always display the custom tab in request editors
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
        return nativeEditor.isModified();
    }
}
