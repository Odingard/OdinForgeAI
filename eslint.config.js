import tseslint from "typescript-eslint";
import security from "eslint-plugin-security";

export default [
  {
    ignores: [
      "node_modules/**",
      "dist/**",
      "*.min.js",
      "odinforge-agent/**",
    ],
  },
  ...tseslint.configs.recommended,
  security.configs.recommended,
  {
    files: ["**/*.ts", "**/*.tsx", "**/*.js"],
    rules: {
      // Disable non-security typescript-eslint rules — we only care about security
      "@typescript-eslint/no-explicit-any": "off",
      "@typescript-eslint/no-unused-vars": "off",
      "@typescript-eslint/no-require-imports": "off",
      "@typescript-eslint/no-empty-object-type": "off",
      "@typescript-eslint/no-unused-expressions": "off",
      "@typescript-eslint/ban-ts-comment": "off",
      "@typescript-eslint/no-wrapper-object-types": "off",
      "prefer-const": "off",
      "no-case-declarations": "off",
      // Tune down noisy security rules for Express codebase
      "security/detect-object-injection": "warn",
      "security/detect-non-literal-fs-filename": "warn",
    },
  },
];
