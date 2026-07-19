package burp;

import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

public class VariableExtractionRule {
    private boolean enabled;
    private String matchUrl;
    private String source; // "body" or "headers"
    private String regex;

    // Saved request fields for token auto-refresh
    private String savedRequestBase64 = "";
    private String savedHost = "";
    private int savedPort = 0;
    private boolean savedSecure = false;

    public VariableExtractionRule() {
        this.enabled = false;
        this.matchUrl = "";
        this.source = "body";
        this.regex = "";
    }

    public VariableExtractionRule(boolean enabled, String matchUrl, String source, String regex) {
        this.enabled = enabled;
        this.matchUrl = matchUrl != null ? matchUrl : "";
        this.source = source != null ? source : "body";
        this.regex = regex != null ? regex : "";
    }

    public VariableExtractionRule(boolean enabled, String matchUrl, String source, String regex, 
                                  String savedRequestBase64, String savedHost, int savedPort, boolean savedSecure) {
        this.enabled = enabled;
        this.matchUrl = matchUrl != null ? matchUrl : "";
        this.source = source != null ? source : "body";
        this.regex = regex != null ? regex : "";
        this.savedRequestBase64 = savedRequestBase64 != null ? savedRequestBase64 : "";
        this.savedHost = savedHost != null ? savedHost : "";
        this.savedPort = savedPort;
        this.savedSecure = savedSecure;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public String getMatchUrl() {
        return matchUrl;
    }

    public void setMatchUrl(String matchUrl) {
        this.matchUrl = matchUrl;
    }

    public String getSource() {
        return source;
    }

    public void setSource(String source) {
        this.source = source;
    }

    public String getRegex() {
        return regex;
    }

    public void setRegex(String regex) {
        this.regex = regex;
    }

    public String getSavedRequestBase64() {
        return savedRequestBase64;
    }

    public void setSavedRequestBase64(String savedRequestBase64) {
        this.savedRequestBase64 = savedRequestBase64;
    }

    public String getSavedHost() {
        return savedHost;
    }

    public void setSavedHost(String savedHost) {
        this.savedHost = savedHost;
    }

    public int getSavedPort() {
        return savedPort;
    }

    public void setSavedPort(int savedPort) {
        this.savedPort = savedPort;
    }

    public boolean isSavedSecure() {
        return savedSecure;
    }

    public void setSavedSecure(boolean savedSecure) {
        this.savedSecure = savedSecure;
    }

    // Serialize to string safe for splitting with '|'
    public String serialize() {
        try {
            return URLEncoder.encode(matchUrl, StandardCharsets.UTF_8.name()) + "|" +
                   URLEncoder.encode(source, StandardCharsets.UTF_8.name()) + "|" +
                   enabled + "|" +
                   URLEncoder.encode(regex, StandardCharsets.UTF_8.name()) + "|" +
                   savedRequestBase64 + "|" +
                   URLEncoder.encode(savedHost, StandardCharsets.UTF_8.name()) + "|" +
                   savedPort + "|" +
                   savedSecure;
        } catch (Exception e) {
            return "";
        }
    }

    // Deserialize from string (handles older versions gracefully)
    public static VariableExtractionRule deserialize(String data) {
        if (data == null || data.isEmpty()) {
            return new VariableExtractionRule();
        }
        try {
            String[] parts = data.split("\\|", -1);
            if (parts.length >= 8) {
                String matchUrl = URLDecoder.decode(parts[0], StandardCharsets.UTF_8.name());
                String source = URLDecoder.decode(parts[1], StandardCharsets.UTF_8.name());
                boolean enabled = Boolean.parseBoolean(parts[2]);
                String regex = URLDecoder.decode(parts[3], StandardCharsets.UTF_8.name());
                String savedRequestBase64 = parts[4];
                String savedHost = URLDecoder.decode(parts[5], StandardCharsets.UTF_8.name());
                int savedPort = Integer.parseInt(parts[6]);
                boolean savedSecure = Boolean.parseBoolean(parts[7]);

                return new VariableExtractionRule(enabled, matchUrl, source, regex, 
                        savedRequestBase64, savedHost, savedPort, savedSecure);
            } else if (parts.length >= 4) {
                String matchUrl = URLDecoder.decode(parts[0], StandardCharsets.UTF_8.name());
                String source = URLDecoder.decode(parts[1], StandardCharsets.UTF_8.name());
                boolean enabled = Boolean.parseBoolean(parts[2]);
                String regex = URLDecoder.decode(parts[3], StandardCharsets.UTF_8.name());
                return new VariableExtractionRule(enabled, matchUrl, source, regex);
            }
        } catch (Exception e) {
            // Ignore and return default
        }
        return new VariableExtractionRule();
    }
}
