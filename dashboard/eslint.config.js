import js from "@eslint/js";
import tseslint from "typescript-eslint";
import reactHooks from "eslint-plugin-react-hooks";
import globals from "globals";

export default tseslint.config(
  { ignores: ["dist", "node_modules", "playwright-report", "test-results"] },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    files: ["**/*.{ts,tsx}"],
    languageOptions: { globals: { ...globals.browser } },
    plugins: { "react-hooks": reactHooks },
    rules: {
      ...reactHooks.configs.recommended.rules,
      // Server strings must be rendered as text, and the CSP forbids inline styles.
      "no-restricted-syntax": [
        "error",
        {
          selector: "JSXAttribute[name.name='dangerouslySetInnerHTML']",
          message: "dangerouslySetInnerHTML is banned: render server data as text.",
        },
        {
          selector: "JSXAttribute[name.name='style']",
          message: "Inline style attributes violate the CSP (style-src 'self'); use a CSS class.",
        },
        {
          selector: "MemberExpression[property.name='innerHTML']",
          message: "innerHTML is banned.",
        },
      ],
      "no-eval": "error",
      "no-implied-eval": "error",
    },
  },
  {
    files: ["e2e/**/*.ts", "playwright.config.ts", "vite.config.ts"],
    languageOptions: { globals: { ...globals.node } },
  },
);
