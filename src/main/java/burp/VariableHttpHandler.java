package burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.handler.*;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class VariableHttpHandler implements HttpHandler {
    private final MontoyaApi api;
    private final VariableManager variableManager;

    // Thread-safe caches to trace requests and variables across interception stages
    private final Map<Integer, HttpRequest> originalTemplates = new ConcurrentHashMap<>();
    private final Map<Integer, Set<String>> requestVariablesUsed = new ConcurrentHashMap<>();

    public VariableHttpHandler(MontoyaApi api, VariableManager variableManager) {
        this.api = api;
        this.variableManager = variableManager;
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
        // Determine if replacement is enabled for this tool
        boolean isEnabled = false;
        if (variableManager.isReplacementMasterEnabled()) {
            if (requestToBeSent.toolSource().isFromTool(ToolType.REPEATER)) {
                isEnabled = variableManager.isReplacementEnabled();
            } else if (requestToBeSent.toolSource().isFromTool(ToolType.INTRUDER)) {
                isEnabled = variableManager.isReplacementIntruderEnabled();
            } else if (requestToBeSent.toolSource().isFromTool(ToolType.SCANNER)) {
                isEnabled = variableManager.isReplacementScannerEnabled();
            }
        }

        if (isEnabled) {
            Map<String, String> variables = variableManager.getVariables();
            if (!variables.isEmpty()) {
                // Check which variables are present in the request template
                Set<String> variablesUsed = new HashSet<>();
                for (String name : variables.keySet()) {
                    String placeholder = "{{" + name + "}}";
                    boolean used = false;
                    
                    if (requestToBeSent.path().contains(placeholder)) {
                        used = true;
                    }
                    if (!used) {
                        for (HttpHeader h : requestToBeSent.headers()) {
                            if (h.value().contains(placeholder)) {
                                used = true;
                                break;
                            }
                        }
                    }
                    if (!used && requestToBeSent.bodyToString() != null && requestToBeSent.bodyToString().contains(placeholder)) {
                        used = true;
                    }

                    if (used) {
                        variablesUsed.add(name);
                    }
                }

                // If placeholders were used, save the template and variable names for response interception
                if (!variablesUsed.isEmpty()) {
                    int messageId = requestToBeSent.messageId();
                    
                    // Store a template copy of the request before replacement
                    HttpRequest template = HttpRequest.httpRequest(requestToBeSent.httpService(), requestToBeSent.toByteArray());
                    originalTemplates.put(messageId, template);
                    requestVariablesUsed.put(messageId, variablesUsed);

                    // Perform replacement
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
        }
        return RequestToBeSentAction.continueWith(requestToBeSent);
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
        int messageId = responseReceived.messageId();
        
        // Clean up maps to prevent memory leaks in large projects
        HttpRequest originalTemplate = originalTemplates.remove(messageId);
        Set<String> varsUsed = requestVariablesUsed.remove(messageId);

        // 1. Always run auto-extraction on normal responses first (if enabled)
        if (variableManager.isExtractionEnabled()) {
            HttpRequest initiatingRequest = responseReceived.initiatingRequest();
            if (initiatingRequest != null) {
                runExtraction(initiatingRequest.path(), responseReceived.headers(), responseReceived.bodyToString());
            }
        }

        // 2. Detect session expiration for requests that used variables
        short statusCode = responseReceived.statusCode();
        Set<Integer> triggerCodes = variableManager.getRefreshStatusCodes();
        if (triggerCodes.contains((int) statusCode) && varsUsed != null && !varsUsed.isEmpty() && originalTemplate != null) {
            api.logging().logToOutput("Session expiration (HTTP " + statusCode + ") detected for message " + messageId + ". Refreshing variables: " + varsUsed);
            
            boolean refreshedAny = false;
            Map<String, VariableExtractionRule> rules = variableManager.getRules();
            
            // Execute synchronous refreshes for expired variables
            for (String varName : varsUsed) {
                VariableExtractionRule rule = rules.get(varName);
                if (rule != null && rule.getSavedRequestBase64() != null && !rule.getSavedRequestBase64().isEmpty()) {
                    try {
                        api.logging().logToOutput("Auto-refreshing variable '" + varName + "' using saved request template...");
                        variableManager.refreshVariableSynchronously(varName, rule);
                        refreshedAny = true;
                    } catch (Exception ex) {
                        api.logging().logToError("Failed to auto-refresh variable '" + varName + "': " + ex.getMessage());
                    }
                }
            }

            if (refreshedAny) {
                // Re-inject the new variable values into the original template request
                Map<String, String> variables = variableManager.getVariables();
                HttpRequest refreshedRequest = originalTemplate;
                
                // 1. Path replacement
                String path = refreshedRequest.path();
                String newPath = replacePlaceholders(path, variables);
                if (!path.equals(newPath)) {
                    refreshedRequest = refreshedRequest.withPath(newPath);
                }

                // 2. Headers replacement
                List<HttpHeader> headers = refreshedRequest.headers();
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
                    refreshedRequest = refreshedRequest.withRemovedHeaders(refreshedRequest.headers()).withAddedHeaders(newHeaders);
                }

                // 3. Body replacement
                String body = refreshedRequest.bodyToString();
                if (body != null && !body.isEmpty()) {
                    String newBody = replacePlaceholders(body, variables);
                    if (!body.equals(newBody)) {
                        refreshedRequest = refreshedRequest.withBody(newBody);
                    }
                }

                try {
                    api.logging().logToOutput("Re-sending refreshed request for message " + messageId + "...");
                    
                    // Re-send the request programmatically
                    HttpRequestResponse refreshedResult = api.http().sendRequest(refreshedRequest);
                    
                    if (refreshedResult.response() != null) {
                        api.logging().logToOutput("Successfully refreshed session (HTTP " + refreshedResult.response().statusCode() + "). Transmitting new response.");
                        
                        // Extract any new tokens from the refreshed response
                        if (variableManager.isExtractionEnabled()) {
                            runExtraction(
                                    refreshedResult.request().path(), 
                                    refreshedResult.response().headers(), 
                                    refreshedResult.response().bodyToString()
                            );
                        }

                        // Transparently return the successful response instead of the 401/403
                        return ResponseReceivedAction.continueWith(refreshedResult.response());
                    }
                } catch (Exception ex) {
                    api.logging().logToError("Failed to re-send refreshed request: " + ex.getMessage());
                }
            }
        }

        return ResponseReceivedAction.continueWith(responseReceived);
    }

    private void runExtraction(String path, List<HttpHeader> headers, String body) {
        Map<String, VariableExtractionRule> rules = variableManager.getRules();

        for (Map.Entry<String, VariableExtractionRule> entry : rules.entrySet()) {
            String varName = entry.getKey();
            VariableExtractionRule rule = entry.getValue();

            if (rule.isEnabled() && rule.getRegex() != null && !rule.getRegex().isEmpty()) {
                boolean pathMatches = false;
                if (rule.getMatchUrl() == null || rule.getMatchUrl().isEmpty()) {
                    pathMatches = true;
                } else {
                    try {
                        Pattern pathPattern = Pattern.compile(rule.getMatchUrl());
                        if (pathPattern.matcher(path).find()) {
                            pathMatches = true;
                        }
                    } catch (Exception e) {
                        pathMatches = path.contains(rule.getMatchUrl());
                    }
                }

                if (pathMatches) {
                    String sourceContent = "";
                    if ("headers".equalsIgnoreCase(rule.getSource())) {
                        StringBuilder sb = new StringBuilder();
                        for (HttpHeader header : headers) {
                            sb.append(header.name()).append(": ").append(header.value()).append("\r\n");
                        }
                        sourceContent = sb.toString();
                    } else {
                        sourceContent = body;
                    }

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
