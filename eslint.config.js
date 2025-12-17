import { defineConfig, globalIgnores } from "eslint/config";
import js from "@eslint/js";
import ts from "typescript-eslint";

export default defineConfig([
  globalIgnores([
    "**/build/**",
    "**/node_modules/**",
    "**/dist/**",
    "**/postgres-data/**",
    "**/playwright-report/**",
    "**/public/**",
    "**/coverage/**",
  ]),
  {
    basePath: "src",
    files: ["**/*.ts"],
    plugins: {
      js,
      ts,
    },
    languageOptions: {
      parser: ts.parser,
      parserOptions: {
        projectService: true,
      },
    },
    extends: ["js/recommended", "ts/recommended"],
    rules: {
      "prefer-const": "error",
      "no-console": [
        "error",
        { allow: ["error", "debug", "log", "info", "warn"] },
      ],
    },
  },
]);
