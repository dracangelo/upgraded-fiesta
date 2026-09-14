import js from "@eslint/js";

export default [
  js.configs.recommended,
  {
    files: ["**/*.js", "**/*.mjs"],
    languageOptions: {
      ecmaVersion: 2024,
      sourceType: "module",
      globals: { console: "readonly", TextDecoder: "readonly" },
    },
    rules: { "no-console": "off" },
  },
  {
    files: ["dashboard.jsx", "dashboard_components.jsx"],
    languageOptions: {
      parserOptions: { ecmaFeatures: { jsx: true } },
      globals: {
        React: "readonly", ReactDOM: "readonly", asList: "readonly",
        document: "readonly", location: "readonly", localStorage: "readonly",
        fetch: "readonly", WebSocket: "readonly", EventSource: "readonly",
        URLSearchParams: "readonly", URL: "readonly", Blob: "readonly", setInterval: "readonly", clearInterval: "readonly",
        console: "readonly", prompt: "readonly", alert: "readonly",
      },
    },
    rules: { "no-unused-vars": "off", "no-empty": "off" },
  },
];
