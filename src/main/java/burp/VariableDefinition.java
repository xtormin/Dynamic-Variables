package burp;

import java.util.Objects;
import java.util.UUID;

public final class VariableDefinition {
    private final String id;
    private String name;
    private String folderId;
    private String value;
    private VariableExtractionRule rule;
    private int position;

    public VariableDefinition(String name, String folderId, String value,
                              VariableExtractionRule rule, int position) {
        this(UUID.randomUUID().toString(), name, folderId, value, rule, position);
    }

    public VariableDefinition(String id, String name, String folderId, String value,
                              VariableExtractionRule rule, int position) {
        this.id = Objects.requireNonNull(id);
        this.name = Objects.requireNonNull(name);
        this.folderId = folderId;
        this.value = value == null ? "" : value;
        this.rule = rule == null ? new VariableExtractionRule() : rule;
        this.position = position;
    }

    public String getId() { return id; }
    public String getName() { return name; }
    public void setName(String name) { this.name = Objects.requireNonNull(name); }
    public String getFolderId() { return folderId; }
    public void setFolderId(String folderId) { this.folderId = folderId; }
    public String getValue() { return value; }
    public void setValue(String value) { this.value = value == null ? "" : value; }
    public VariableExtractionRule getRule() { return rule; }
    public void setRule(VariableExtractionRule rule) { this.rule = rule == null ? new VariableExtractionRule() : rule; }
    public int getPosition() { return position; }
    public void setPosition(int position) { this.position = position; }

    public String qualifiedName(VariableFolder folder) {
        return folder == null ? name : folder.getName() + "." + name;
    }
}
