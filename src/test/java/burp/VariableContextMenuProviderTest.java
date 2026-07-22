package burp;

import burp.api.montoya.core.ToolType;
import burp.api.montoya.ui.contextmenu.InvocationType;
import burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class VariableContextMenuProviderTest {
    @Test
    void offersMaterializationOnlyInRepeaterRequestEditors() {
        assertTrue(VariableContextMenuProvider.isMaterializationContext(
                ToolType.REPEATER,
                InvocationType.MESSAGE_EDITOR_REQUEST,
                MessageEditorHttpRequestResponse.SelectionContext.REQUEST));

        assertFalse(VariableContextMenuProvider.isMaterializationContext(
                ToolType.PROXY,
                InvocationType.MESSAGE_EDITOR_REQUEST,
                MessageEditorHttpRequestResponse.SelectionContext.REQUEST));
        assertFalse(VariableContextMenuProvider.isMaterializationContext(
                ToolType.REPEATER,
                InvocationType.MESSAGE_VIEWER_REQUEST,
                MessageEditorHttpRequestResponse.SelectionContext.REQUEST));
        assertFalse(VariableContextMenuProvider.isMaterializationContext(
                ToolType.REPEATER,
                InvocationType.MESSAGE_EDITOR_RESPONSE,
                MessageEditorHttpRequestResponse.SelectionContext.RESPONSE));
    }
}
