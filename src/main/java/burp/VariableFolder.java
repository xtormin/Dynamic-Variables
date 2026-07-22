package burp;

import java.util.Objects;
import java.util.UUID;

public final class VariableFolder {
    private final String id;
    private String name;
    private int position;
    private boolean expanded;

    public VariableFolder(String name, int position) {
        this(UUID.randomUUID().toString(), name, position, true);
    }

    public VariableFolder(String id, String name, int position, boolean expanded) {
        this.id = Objects.requireNonNull(id);
        this.name = Objects.requireNonNull(name);
        this.position = position;
        this.expanded = expanded;
    }

    public String getId() { return id; }
    public String getName() { return name; }
    public void setName(String name) { this.name = Objects.requireNonNull(name); }
    public int getPosition() { return position; }
    public void setPosition(int position) { this.position = position; }
    public boolean isExpanded() { return expanded; }
    public void setExpanded(boolean expanded) { this.expanded = expanded; }
}
