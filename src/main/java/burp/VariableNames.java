package burp;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

final class VariableNames {
    private static final Pattern PLACEHOLDER = Pattern.compile("\\{\\{([^{}]+)}}");
    private static final Pattern QUALIFIED_PLACEHOLDER = Pattern.compile("\\{\\{([^{}.]+)\\.([^{}.]+)}}");

    private VariableNames() {}

    record FolderRemapResult(String text, List<String> replacedVariables, List<String> unmatchedVariables) {
        boolean changed() {
            return !replacedVariables.isEmpty();
        }
    }

    record MaterializationResult(String text, List<String> replacedVariables, List<String> unresolvedVariables) {
        boolean changed() {
            return !replacedVariables.isEmpty();
        }

        boolean hasPlaceholders() {
            return changed() || !unresolvedVariables.isEmpty();
        }
    }

    static boolean isValidComponent(String name) {
        return name != null && !name.trim().isEmpty() && !name.contains(".");
    }

    static String qualify(String folder, String variable) {
        return folder == null || folder.isEmpty() ? variable : folder + "." + variable;
    }

    static String replacePlaceholders(String text, Map<String, String> variables) {
        return materializePlaceholders(text, variables).text();
    }

    static MaterializationResult materializePlaceholders(String text, Map<String, String> variables) {
        if (text == null || text.isEmpty()) {
            return new MaterializationResult(text, List.of(), List.of());
        }

        Map<String, String> availableVariables = variables == null ? Map.of() : variables;
        Matcher matcher = PLACEHOLDER.matcher(text);
        StringBuffer rewritten = new StringBuffer();
        Set<String> replaced = new LinkedHashSet<>();
        Set<String> unresolved = new LinkedHashSet<>();

        while (matcher.find()) {
            String variableName = matcher.group(1);
            String value = availableVariables.get(variableName);
            if (value != null) {
                matcher.appendReplacement(rewritten, Matcher.quoteReplacement(value));
                replaced.add(variableName);
            } else {
                matcher.appendReplacement(rewritten, Matcher.quoteReplacement(matcher.group()));
                unresolved.add(variableName);
            }
        }
        matcher.appendTail(rewritten);

        return new MaterializationResult(rewritten.toString(), List.copyOf(replaced), List.copyOf(unresolved));
    }

    static List<String> detectPlaceholderFolders(String text) {
        if (text == null || text.isEmpty()) return List.of();
        Set<String> folders = new LinkedHashSet<>();
        Matcher matcher = QUALIFIED_PLACEHOLDER.matcher(text);
        while (matcher.find()) folders.add(matcher.group(1));
        return List.copyOf(folders);
    }

    static FolderRemapResult remapFolderPlaceholders(String text, String sourceFolder, String targetFolder,
                                                       Set<String> targetLocalNames) {
        if (text == null || text.isEmpty() || sourceFolder == null || targetFolder == null
                || sourceFolder.equals(targetFolder)) {
            return new FolderRemapResult(text, List.of(), List.of());
        }

        Set<String> availableTargets = targetLocalNames == null ? Set.of() : targetLocalNames;
        Pattern sourcePlaceholder = Pattern.compile("\\{\\{" + Pattern.quote(sourceFolder)
                + "\\.([^{}.]+)}}");
        Matcher matcher = sourcePlaceholder.matcher(text);
        StringBuffer rewritten = new StringBuffer();
        Set<String> replaced = new LinkedHashSet<>();
        Set<String> unmatched = new LinkedHashSet<>();

        while (matcher.find()) {
            String localName = matcher.group(1);
            if (availableTargets.contains(localName)) {
                matcher.appendReplacement(rewritten, Matcher.quoteReplacement("{{" + targetFolder + "." + localName + "}}"));
                replaced.add(localName);
            } else {
                matcher.appendReplacement(rewritten, Matcher.quoteReplacement(matcher.group()));
                unmatched.add(localName);
            }
        }
        matcher.appendTail(rewritten);

        return new FolderRemapResult(rewritten.toString(), List.copyOf(replaced), List.copyOf(unmatched));
    }
}
