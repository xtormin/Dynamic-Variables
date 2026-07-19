# Dynamic Variables — Burp Suite Extension

> **Placeholder-based request variables and auto-extraction rules with native background token refreshing for Burp Suite.**

Dynamic Variables is a Burp Suite extension that brings template variables and automatic session refreshes to your pentesting workflow. Define placeholders like `{{token}}` in Repeater requests (similar to how it is done in Postman), select text in HTTP responses to auto-generate regex extraction rules, and repeat login/refresh requests with a single click in the background when your session expires.

---

## Index

- [Features](#features)
- [Screenshots](#screenshots)
- [How to Use](#how-to-use)
- [Use Cases for Pentesters](#use-cases-for-pentesters)
- [Installation](#installation)
- [Dependencies](#dependencies)
- [License](#license)

---

## Features

| # | Feature | Description |
|---|---------|-------------|
| 1 | **Placeholder Substitution** | Scans outgoing Repeater requests (URL path, headers, and body) for `{{variable_name}}` templates and replaces them with their actual values in real-time. |
| 2 | **Regex Auto-Deduction** | Highlight any token (JWT, cookie, JWE, anti-CSRF) in a response, right-click, and select *Assign to Variable...*. The scanner auto-generates the matching regex for JSON keys, query params, or XML tags. |
| 3 | **Variables Dashboard** | A centralized tab in Burp Suite to manage variable values, auto-extraction rules, and background request execution. |
| 4 | **Request Auto-Refreshing** | Saves the request template that generated your token (e.g., login or auth endpoint). Re-sends it instantly in a background thread from the tab to fetch a fresh token. |
| 5 | **Recursive Injection** | If your saved refresh request itself depends on other variables (like credentials or client keys), they are substituted automatically before launching the request. |
| 6 | **Interactive Rule Editor** | Click *Update Rule from Response...* to run the saved request and highlight the new token value directly in a raw HTTP response editor to auto-update the regex rule. |
| 7 | **Repeater Integration** | Send your saved login/refresh requests directly to the Repeater tab for manual tweaking and testing. |
| 8 | **Zero Dependencies** | Built using the native Montoya API. No external libraries, 100% self-contained JAR. |

---

## Screenshots

*(Create an `images/` directory in your repository and save screenshots of the tab and the JDialog dialogs to display them here)*

| Variables Suite Tab | Assign to Variable (Context Menu) |
|:---:|:---:|
| ![Variables Dashboard with Table, Value Editor, and Refresh Panel](images/dashboard.png) | ![Popup dialog with regex auto-deduction](images/assign_to_variable.png) |

---

## How to Use

### 1. Define a Variable Manually
1. Open the **Variables** tab in Burp Suite.
2. Click **Add Variable** and enter a name (e.g., `api_key`).
3. Select `api_key` in the table, and paste the value in the **Variable Value Editor** on the right.
4. In Repeater, reference it as `{{api_key}}` (e.g., `Authorization: Bearer {{api_key}}`). It will be substituted when the request is sent.

### 2. Auto-Extract Variables from Responses
1. Send a request that returns a token in the response (e.g., login request).
2. Go to the **Response** viewer tab.
3. Highlight the token value inside the response body or headers.
4. Right-click the highlighted text and click **Assign to Variable...**.
5. Select or type a variable name. The **Regex Pattern** is automatically generated for you.
6. Make sure **"Save this request to refresh token in the future"** is checked.
7. Click **Save Rule**.

### 3. Background Token Refreshing
1. When your session token expires, click on the **Variables** tab.
2. Select your variable (e.g., `jwt`).
3. Under the **Token Refresh Request** panel at the top-right, you will see `Saved Request: POST /api/login`.
4. Click **Refresh Variable**.
5. The extension executes the saved request template in the background, applies the regex pattern on the response, updates the variable value instantly, and shows a success notification.

### 4. Interactive Rule Updating
1. If the API response structure changes, select your variable in the table.
2. Click **Update Rule from Response...**.
3. The plugin fetches a fresh response from the server and displays it in a raw viewer.
4. Highlight the new token location in this viewer to immediately regenerate the regex pattern.
5. Click **Save Extraction Rule** to save changes.

---

## Use Cases for Pentesters

| Scenario | How it helps |
|----------|--------------|
| **JWT/JWE Rotation** | Set up a regex extraction rule on the login endpoint response. The JWT variable updates dynamically whenever you send a login or authenticate request, updating all active Repeater templates. |
| **Session Cookie Refresh** | Extract cookie headers (`Set-Cookie: session=([^;]+)`) and replace them in all target Repeater tabs using `Cookie: session={{session_cookie}}`. |
| **Anti-CSRF Protection** | Extract CSRF tokens from HTML bodies or header responses. The token replaces `{{csrf_token}}` automatically on POST parameters. |
| **Credential Management** | Store your testing passwords or administrative user logins as variables, and change them once globally to update all your fuzzing/repeating setups. |

---

## Installation

### Requirements
- **Java**: JDK 17 or later
- **Burp Suite**: Any edition compatible with Montoya API (2023.12+)

### Build from Source

The project uses Gradle to produce a clean, lightweight JAR file:

```bash
./gradlew build
```

The output JAR will be created at:
```
build/libs/dynamic-variables-1.0.jar
```

### Load in Burp Suite

1. Open Burp Suite.
2. Go to **Extensions** → **Installed**.
3. Click **Add**.
4. Set **Extension type** to `Java`.
5. Select the compiled `dynamic-variables-1.0.jar` file and click **Next**.

---

## Dependencies

- Burp Suite Montoya API (provided by the Burp environment).
- Zero third-party runtime dependencies.

---

## License

This project is licensed under the **MIT License**.
See [LICENSE](LICENSE) for details.
