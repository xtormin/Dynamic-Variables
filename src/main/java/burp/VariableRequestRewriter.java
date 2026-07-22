package burp;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

final class VariableRequestRewriter {
    record HeaderValue(String name, String value) {}

    record RequestParts(String path, List<HeaderValue> headers, String body) {
        RequestParts {
            headers = headers == null ? List.of() : List.copyOf(headers);
        }
    }

    record RewriteResult(RequestParts request, List<String> variablesUsed) {
        boolean changed() {
            return !variablesUsed.isEmpty();
        }
    }

    private VariableRequestRewriter() {}

    static RewriteResult rewrite(RequestParts request, Map<String, String> variables,
                                 VariableNames.PlaceholderStyle placeholderStyle) {
        if (request == null) {
            throw new IllegalArgumentException("Request parts cannot be null");
        }

        Set<String> variablesUsed = new LinkedHashSet<>();
        VariableNames.MaterializationResult path = VariableNames.materializePlaceholders(
                request.path(), variables, placeholderStyle);
        variablesUsed.addAll(path.replacedVariables());

        List<HeaderValue> headers = new ArrayList<>(request.headers().size());
        for (HeaderValue header : request.headers()) {
            VariableNames.MaterializationResult value = VariableNames.materializePlaceholders(
                    header.value(), variables, placeholderStyle);
            variablesUsed.addAll(value.replacedVariables());
            headers.add(Objects.equals(header.value(), value.text())
                    ? header : new HeaderValue(header.name(), value.text()));
        }

        VariableNames.MaterializationResult body = VariableNames.materializePlaceholders(
                request.body(), variables, placeholderStyle);
        variablesUsed.addAll(body.replacedVariables());

        RequestParts rewritten = new RequestParts(path.text(), headers, body.text());
        return new RewriteResult(rewritten, List.copyOf(variablesUsed));
    }
}
