package burp;

import java.util.Map;

final class VariableNames {
    private VariableNames() {}

    static boolean isValidComponent(String name) {
        return name != null && !name.trim().isEmpty() && !name.contains(".");
    }

    static String qualify(String folder, String variable) {
        return folder == null || folder.isEmpty() ? variable : folder + "." + variable;
    }

    static String replacePlaceholders(String text, Map<String, String> variables) {
        if (text == null || text.isEmpty()) return text;
        String result = text;
        for (Map.Entry<String, String> entry : variables.entrySet()) {
            String placeholder = "{{" + entry.getKey() + "}}";
            if (result.contains(placeholder)) result = result.replace(placeholder, entry.getValue());
        }
        return result;
    }
}
