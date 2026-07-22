package burp;

import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.Set;

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

    @Test
    void detectsQualifiedPlaceholderFoldersInFirstSeenOrder() {
        assertEquals(java.util.List.of("user1", "other"),
                VariableNames.detectPlaceholderFolders("{{user1.jwe}} {{global}} {{other.id}} {{user1.accountId}}"));
    }

    @Test
    void remapsMatchingVariablesAndReportsUnmatchedOnes() {
        String requestPart = "/accounts/{{user1.accountId}}?token={{user1.jwe}}&missing={{user1.onlyHere}}";

        VariableNames.FolderRemapResult result = VariableNames.remapFolderPlaceholders(
                requestPart, "user1", "user2", Set.of("jwe", "accountId"));

        assertEquals("/accounts/{{user2.accountId}}?token={{user2.jwe}}&missing={{user1.onlyHere}}", result.text());
        assertEquals(java.util.List.of("accountId", "jwe"), result.replacedVariables());
        assertEquals(java.util.List.of("onlyHere"), result.unmatchedVariables());
        assertTrue(result.changed());
    }

    @Test
    void remapsPlaceholdersAcrossPathHeadersAndBodyText() {
        String requestSections = "/users/{{user1.accountId}}\n"
                + "Authorization: Bearer {{user1.jwe}}\n"
                + "{\"owner\":\"{{user1.accountId}}\"}";

        VariableNames.FolderRemapResult result = VariableNames.remapFolderPlaceholders(
                requestSections, "user1", "user2", Set.of("jwe", "accountId"));

        assertEquals("/users/{{user2.accountId}}\n"
                + "Authorization: Bearer {{user2.jwe}}\n"
                + "{\"owner\":\"{{user2.accountId}}\"}", result.text());
    }

    @Test
    void remappingIsExactAndPreservesOtherKindsOfVariables() {
        String text = "id={{user1.id}} account={{user1.accountId}} global={{id}} other={{user3.id}}";

        VariableNames.FolderRemapResult result = VariableNames.remapFolderPlaceholders(
                text, "user1", "user2", Set.of("id"));

        assertEquals("id={{user2.id}} account={{user1.accountId}} global={{id}} other={{user3.id}}", result.text());
        assertEquals(java.util.List.of("id"), result.replacedVariables());
        assertEquals(java.util.List.of("accountId"), result.unmatchedVariables());
    }

    @Test
    void leavesPlainTextAndUnusableRemapsUnchanged() {
        assertFalse(VariableNames.remapFolderPlaceholders(
                "ordinary user1.id text", "user1", "user2", Set.of("id")).changed());
        assertFalse(VariableNames.remapFolderPlaceholders(
                "{{user1.id}}", "user1", "user1", Set.of("id")).changed());
        assertFalse(VariableNames.remapFolderPlaceholders(
                "{{user1.id}}", "user1", "user2", Set.of("accountId")).changed());
    }
}
