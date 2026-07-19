package burp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;

public class DynamicVariables implements BurpExtension {
    @Override
    public void initialize(MontoyaApi api) {
        // Set extension name
        api.extension().setName("Dynamic Variables");

        // Initialize state and UI manager
        VariableManager variableManager = new VariableManager(api);

        // Register custom tab in Burp Suite
        api.userInterface().registerSuiteTab("Variables", variableManager.getTabComponent());

        // Register HttpHandler for request substitution and response extraction
        api.http().registerHttpHandler(new VariableHttpHandler(api, variableManager));

        // Register ContextMenu provider for response selection to variables mapping
        api.userInterface().registerContextMenuItemsProvider(new VariableContextMenuProvider(api, variableManager));

        // Register clean unload handler to comply with BApp Store guidelines
        api.extension().registerUnloadingHandler(() -> {
            api.logging().logToOutput("Dynamic Variables Extension unloaded successfully.");
        });

        api.logging().logToOutput("Dynamic Variables Extension loaded successfully!");
        api.logging().logToOutput("Define variables in the 'Variables' tab and use {{variable_name}} in Repeater requests.");
    }
}
