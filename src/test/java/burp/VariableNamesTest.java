package burp;

import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class VariableNamesTest {
    @Test
    void qualifiesFolderVariablesAndLeavesRootVariablesUnchanged() {
        assertEquals("token", VariableNames.qualify("", "token"));
        assertEquals("token", VariableNames.qualify(null, "token"));
        assertEquals("alice.token", VariableNames.qualify("alice", "token"));
        assertNotEquals(VariableNames.qualify("alice", "token"), VariableNames.qualify("bob", "token"));
    }

    @Test
    void validatesNewFolderAndVariableComponents() {
        assertTrue(VariableNames.isValidComponent("alice"));
        assertTrue(VariableNames.isValidComponent("session_token"));
        assertFalse(VariableNames.isValidComponent(null));
        assertFalse(VariableNames.isValidComponent("  "));
        assertFalse(VariableNames.isValidComponent("alice.token"));
    }

    @Test
    void replacesSameLocalNameIndependentlyAcrossFolders() {
        String request = "Alice={{alice.token}}&Bob={{bob.token}}&Global={{api_url}}";
        assertEquals("Alice=alice-secret&Bob=bob-secret&Global=https://example.test",
                VariableNames.replacePlaceholders(request, Map.of(
                        "alice.token", "alice-secret",
                        "bob.token", "bob-secret",
                        "api_url", "https://example.test")));
    }
}
