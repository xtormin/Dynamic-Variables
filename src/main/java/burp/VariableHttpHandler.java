package burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.handler.*;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class VariableHttpHandler implements HttpHandler {
    private final MontoyaApi api;
    private final VariableManager variableManager;

    public VariableHttpHandler(MontoyaApi api, VariableManager variableManager) {
        this.api = api;
        this.variableManager = variableManager;
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
        // Only run replacement for Repeater requests if replacement is enabled
        if (variableManager.isReplacementEnabled() && requestToBeSent.toolSource().isFromTool(ToolType.REPEATER)) {
            Map<String, String> variables = variableManager.getVariables();
            if (!variables.isEmpty()) {
                HttpRequest request = requestToBeSent;

                // 1. Replace in Path/URL
                String path = request.path();
                String newPath = replacePlaceholders(path, variables);
                if (!path.equals(newPath)) {
                    request = request.withPath(newPath);
                }

                // 2. Replace in Headers
                List<HttpHeader> headers = request.headers();
                List<HttpHeader> newHeaders = new ArrayList<>();
                boolean headersModified = false;
                for (HttpHeader header : headers) {
                    String value = header.value();
                    String newValue = replacePlaceholders(value, variables);
                    if (!value.equals(newValue)) {
                        newHeaders.add(HttpHeader.httpHeader(header.name(), newValue));
                        headersModified = true;
                    } else {
                        newHeaders.add(header);
                    }
                }
                if (headersModified) {
                    request = request.withRemovedHeaders(request.headers()).withAddedHeaders(newHeaders);
                }

                // 3. Replace in Body
                String body = request.bodyToString();
                if (body != null && !body.isEmpty()) {
                    String newBody = replacePlaceholders(body, variables);
                    if (!body.equals(newBody)) {
                        request = request.withBody(newBody);
                    }
                }

                return RequestToBeSentAction.continueWith(request);
            }
        }
        return RequestToBeSentAction.continueWith(requestToBeSent);
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
        // Only run extraction if enabled globally
        if (variableManager.isExtractionEnabled()) {
            HttpRequest initiatingRequest = responseReceived.initiatingRequest();
            if (initiatingRequest != null) {
                String path = initiatingRequest.path();
                Map<String, VariableExtractionRule> rules = variableManager.getRules();

                for (Map.Entry<String, VariableExtractionRule> entry : rules.entrySet()) {
                    String varName = entry.getKey();
                    VariableExtractionRule rule = entry.getValue();

                    if (rule.isEnabled() && rule.getRegex() != null && !rule.getRegex().isEmpty()) {
                        // 1. Check if URL/Path matches the filter
                        boolean pathMatches = false;
                        if (rule.getMatchUrl() == null || rule.getMatchUrl().isEmpty()) {
                            pathMatches = true; // empty matches everything
                        } else {
                            try {
                                Pattern pathPattern = Pattern.compile(rule.getMatchUrl());
                                if (pathPattern.matcher(path).find()) {
                                    pathMatches = true;
                                }
                            } catch (Exception e) {
                                // Invalid regex filter in path match, fallback to contains check
                                pathMatches = path.contains(rule.getMatchUrl());
                            }
                        }

                        if (pathMatches) {
                            // 2. Select source content
                            String sourceContent = "";
                            if ("headers".equalsIgnoreCase(rule.getSource())) {
                                StringBuilder sb = new StringBuilder();
                                for (HttpHeader header : responseReceived.headers()) {
                                    sb.append(header.name()).append(": ").append(header.value()).append("\r\n");
                                }
                                sourceContent = sb.toString();
                            } else {
                                sourceContent = responseReceived.bodyToString();
                            }

                            // 3. Apply Regex extraction
                            if (sourceContent != null && !sourceContent.isEmpty()) {
                                try {
                                    Pattern regexPattern = Pattern.compile(rule.getRegex(), Pattern.DOTALL);
                                    Matcher matcher = regexPattern.matcher(sourceContent);
                                    if (matcher.find() && matcher.groupCount() >= 1) {
                                        String extractedValue = matcher.group(1);
                                        if (extractedValue != null) {
                                            variableManager.updateVariableValue(varName, extractedValue);
                                        }
                                    }
                                } catch (Exception e) {
                                    api.logging().logToError("Regex extraction error for variable '" + varName + "': " + e.getMessage());
                                }
                            }
                        }
                    }
                }
            }
        }
        return ResponseReceivedAction.continueWith(responseReceived);
    }

    private String replacePlaceholders(String text, Map<String, String> variables) {
        if (text == null || text.isEmpty()) {
            return text;
        }
        String result = text;
        for (Map.Entry<String, String> entry : variables.entrySet()) {
            String placeholder = "{{" + entry.getKey() + "}}";
            if (result.contains(placeholder)) {
                result = result.replace(placeholder, entry.getValue());
            }
        }
        return result;
    }
}
