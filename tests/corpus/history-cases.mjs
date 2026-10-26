// History corpus: each case is a throwaway git repository the runner builds from `commits`.
//
// Nothing here is a real credential. Every secret-looking value is assembled from fragments at
// run time, so no detector (GitHub push protection, secret scanners) sees a whole token in this
// file, and none of the values was ever issued by a provider.
//
// A case: { rule, kind, name, expect: [rule ids], known?: [{ type: "miss"|"fp", rule, reason }],
// commits: [{ files?: {path: content}, remove?: [path] }] }. `kind` is the directory the case
// would live in if it were a file: "positive" means `rule` is expected, "negative" means it is not.
const join = (...parts) => parts.join("");

const FAKE = {
  github: join("ghp", "_", "Zq8", "aB3cD4eF5g", "Lm4", "hJ6kL7mN8p", "Pw7", "qR9sT0uV1w"),
  githubOld: join("ghp", "_", "R3mOv3dT0k3n", "AbCdEfGhIjKl", "MnOpQrStUvWxYz"),
  aws: join("AKIA", "Q7RT", "M2XW", "9KDP", "L3VZ"),
  awsSecret: join("wJalr", "XUtnFEMI", "K7MDENG", "bPxRfiCY", "Q9z8Rk3mN2pL"),
  stripe: join("sk", "_live_", "4eC39HqLyjWDarjtT1zdp7dc"),
  slack: join("xox", "b-", "2837461950", "-8Kd7sPq1Zr4Nw"),
  google: join("AI", "zaSy", "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q"),
  dbPassword: join("Xq9", "!vR2", "#mT7", "pLw4"),
  pem: join(
    "-----BEGIN ",
    "RSA ",
    "PRIVATE KEY-----\nMIIEowIBAAKCAQEAq7Zt3nXk9pLw4RvB2cYd8Hs1Jf6UeNgA0oTm5VxQzWiKl3Dc\n-----END ",
    "RSA PRIVATE KEY-----\n",
  ),
  urlPassword: join("postgres://app:", "Xq9vR2mT7pLw4", "@db.internal:5432/app"),
};

export const HISTORY_RULES = ["PG-SECRET-001", "PG-SECRET-002", "PG-SECRET-003", "PG-HYGIENE-001"];

export const HISTORY_CASES = [
  // ---- PG-SECRET-001: environment file committed ----
  {
    rule: "PG-SECRET-001",
    kind: "positive",
    name: "dotenv-at-head",
    expect: ["PG-SECRET-001"],
    commits: [{ files: { ".env": "DEBUG=1\nPORT=3000\n", "index.js": "console.log(1);\n" } }],
  },
  {
    rule: "PG-SECRET-001",
    kind: "positive",
    name: "dotenv-local-with-secret",
    expect: ["PG-SECRET-001", "PG-SECRET-002"],
    commits: [{ files: { ".env.local": `STRIPE_KEY=${FAKE.stripe}\n` } }],
  },
  {
    rule: "PG-SECRET-001",
    kind: "positive",
    name: "nested-dotenv",
    expect: ["PG-SECRET-001"],
    commits: [{ files: { "services/api/.env": "NODE_ENV=production\n" } }],
  },
  {
    rule: "PG-SECRET-001",
    kind: "positive",
    name: "named-prod-env",
    expect: ["PG-SECRET-001"],
    commits: [{ files: { "config/prod.env": "REGION=eu\n" } }],
  },
  {
    rule: "PG-SECRET-001",
    kind: "negative",
    name: "dotenv-example",
    expect: [],
    commits: [{ files: { ".env.example": "API_KEY=your-api-key-here\n" } }],
  },
  {
    rule: "PG-SECRET-001",
    kind: "negative",
    name: "dotenv-sample-and-template",
    expect: [],
    commits: [{ files: { ".env.sample": "PORT=3000\n", ".env.template": "PORT=\n" } }],
  },
  {
    rule: "PG-SECRET-001",
    kind: "negative",
    name: "dotenv-gitignored-untracked",
    expect: [],
    commits: [{ files: { ".gitignore": ".env\n", "app.js": "// app\n" } }],
    untracked: { ".env": "PORT=3000\n" },
  },
  {
    rule: "PG-SECRET-001",
    kind: "negative",
    name: "env-word-in-name",
    expect: [],
    commits: [
      { files: { "docs/environment.md": "# Environment\n", "src/env.js": "export {};\n" } },
    ],
  },
  {
    rule: "PG-SECRET-001",
    kind: "positive",
    name: "dotenv-removed-before-head",
    // A removed env file is still in history, so it is reported.
    expect: ["PG-SECRET-001"],
    commits: [{ files: { ".env": "PORT=3000\n" } }, { remove: [".env"] }],
  },

  // ---- PG-SECRET-002: secret in a tracked file ----
  {
    rule: "PG-SECRET-002",
    kind: "positive",
    name: "github-token-in-source",
    expect: ["PG-SECRET-002"],
    commits: [{ files: { "src/deploy.js": `const token = "${FAKE.github}";\n` } }],
  },
  {
    rule: "PG-SECRET-002",
    kind: "positive",
    name: "aws-access-key-id",
    expect: ["PG-SECRET-002"],
    commits: [{ files: { "config/aws.yml": `access_key_id: ${FAKE.aws}\n` } }],
  },
  {
    rule: "PG-SECRET-002",
    kind: "positive",
    name: "private-key-block",
    expect: ["PG-SECRET-002"],
    commits: [{ files: { "certs/server.key": FAKE.pem } }],
  },
  {
    rule: "PG-SECRET-002",
    kind: "positive",
    name: "stripe-live-key",
    expect: ["PG-SECRET-002"],
    commits: [{ files: { "src/billing.ts": `export const KEY = "${FAKE.stripe}";\n` } }],
  },
  {
    rule: "PG-SECRET-002",
    kind: "positive",
    name: "generic-db-password",
    expect: ["PG-SECRET-002"],
    commits: [{ files: { "src/db.js": `const DB_PASSWORD = "${FAKE.dbPassword}";\n` } }],
  },
  {
    rule: "PG-SECRET-002",
    kind: "positive",
    name: "slack-token",
    expect: ["PG-SECRET-002"],
    commits: [{ files: { "bot/config.py": `SLACK_TOKEN = "${FAKE.slack}"\n` } }],
  },
  {
    rule: "PG-SECRET-002",
    kind: "positive",
    name: "google-api-key",
    expect: ["PG-SECRET-002"],
    commits: [{ files: { "web/maps.js": `const KEY = "${FAKE.google}";\n` } }],
  },
  {
    rule: "PG-SECRET-002",
    kind: "positive",
    name: "url-with-password",
    expect: ["PG-SECRET-002"],
    commits: [{ files: { "src/db.go": `package db\n\nconst dsn = "${FAKE.urlPassword}"\n` } }],
  },
  {
    rule: "PG-SECRET-002",
    kind: "negative",
    name: "env-reference",
    expect: [],
    commits: [{ files: { "src/db.js": "const password = process.env.DB_PASSWORD;\n" } }],
  },
  {
    rule: "PG-SECRET-002",
    kind: "negative",
    name: "placeholder-values",
    expect: [],
    commits: [
      {
        files: {
          "README.md": 'Set `api_key = "your-api-key-here"` and `password = changeme123`.\n',
          "config.sample.js": 'module.exports = { password: "<your password>" };\n',
        },
      },
    ],
  },
  {
    rule: "PG-SECRET-002",
    kind: "negative",
    name: "aws-documentation-example-key",
    expect: [],
    commits: [{ files: { "docs/aws.md": `key=${join("AKIA", "IOSFODNN7", "EXAMPLE")}\n` } }],
  },
  {
    rule: "PG-SECRET-002",
    kind: "negative",
    name: "low-entropy-value",
    expect: [],
    commits: [{ files: { "src/cfg.js": 'const password = "aaaaaaaaaaaa";\n' } }],
  },
  {
    rule: "PG-SECRET-002",
    kind: "negative",
    name: "code-that-names-credentials",
    expect: [],
    commits: [
      {
        files: {
          "src/types.ts":
            "export type CredentialKey = string;\nconst PASSWORD_NAME = /^(password|passwd|pwd)$/i;\nfunction setPassword(password: string): void {}\n",
        },
      },
    ],
  },
  {
    rule: "PG-SECRET-002",
    kind: "negative",
    name: "only-in-untracked-file",
    expect: [],
    commits: [{ files: { ".gitignore": "secrets.txt\n" } }],
    untracked: { "secrets.txt": `token=${FAKE.github}\n` },
  },

  // ---- PG-SECRET-003: secret in history ----
  {
    rule: "PG-SECRET-003",
    kind: "positive",
    name: "removed-github-token",
    expect: ["PG-SECRET-003"],
    commits: [
      { files: { "src/deploy.js": `const token = "${FAKE.githubOld}";\n` } },
      { files: { "src/deploy.js": "const token = process.env.GITHUB_TOKEN;\n" } },
    ],
  },
  {
    rule: "PG-SECRET-003",
    kind: "positive",
    name: "deleted-file-with-aws-key",
    expect: ["PG-SECRET-003"],
    commits: [{ files: { "creds.txt": `aws_key=${FAKE.aws}\n` } }, { remove: ["creds.txt"] }],
  },
  {
    rule: "PG-SECRET-003",
    kind: "positive",
    name: "removed-private-key",
    expect: ["PG-SECRET-003"],
    commits: [
      { files: { "deploy/id_rsa": FAKE.pem } },
      { remove: ["deploy/id_rsa"], files: { "README.md": "removed key\n" } },
    ],
  },
  {
    rule: "PG-SECRET-003",
    kind: "positive",
    name: "removed-stripe-key-after-several-commits",
    expect: ["PG-SECRET-003"],
    commits: [
      { files: { "billing.js": `const k = "${FAKE.stripe}";\n` } },
      { files: { "other.js": "export {};\n" } },
      { files: { "billing.js": "const k = process.env.STRIPE_KEY;\n" } },
    ],
  },
  {
    rule: "PG-SECRET-003",
    kind: "negative",
    name: "never-had-a-secret",
    expect: [],
    commits: [{ files: { "a.js": "const a = 1;\n" } }, { files: { "a.js": "const a = 2;\n" } }],
  },
  {
    rule: "PG-SECRET-003",
    kind: "negative",
    name: "secret-still-present-reports-current-only",
    expect: ["PG-SECRET-002"],
    commits: [
      { files: { "src/k.js": `const t = "${FAKE.github}";\n` } },
      { files: { "src/k.js": `// updated\nconst t = "${FAKE.github}";\n` } },
    ],
  },
  {
    rule: "PG-SECRET-003",
    kind: "negative",
    name: "placeholder-in-history",
    expect: [],
    commits: [
      { files: { "src/k.js": 'const password = "changeme123";\n' } },
      { files: { "src/k.js": "const password = process.env.P;\n" } },
    ],
  },
  {
    rule: "PG-SECRET-001",
    kind: "positive",
    name: "env-file-removed-without-secrets",
    // The file is gone from HEAD but was committed once; PG-SECRET-001 still reports it.
    expect: ["PG-SECRET-001"],
    commits: [{ files: { ".env": "PORT=3000\n" } }, { remove: [".env"] }],
  },

  {
    rule: "PG-SECRET-003",
    kind: "negative",
    name: "removed-low-entropy-password",
    expect: [],
    commits: [
      { files: { "src/cfg.js": 'const password = "aaaaaaaaaaaa";\n' } },
      { files: { "src/cfg.js": "const password = process.env.P;\n" } },
    ],
  },

  // ---- PG-HYGIENE-001: dependency directory committed ----
  {
    rule: "PG-HYGIENE-001",
    kind: "positive",
    name: "node-modules-committed",
    expect: ["PG-HYGIENE-001"],
    commits: [{ files: { "node_modules/left-pad/index.js": "module.exports = 1;\n" } }],
  },
  {
    rule: "PG-HYGIENE-001",
    kind: "positive",
    name: "nested-node-modules",
    expect: ["PG-HYGIENE-001"],
    commits: [{ files: { "packages/web/node_modules/a/index.js": "module.exports = 1;\n" } }],
  },
  {
    rule: "PG-HYGIENE-001",
    kind: "positive",
    name: "root-vendor-php",
    expect: ["PG-HYGIENE-001"],
    commits: [
      {
        files: {
          "composer.json": "{}\n",
          "vendor/autoload.php": "<?php\n",
          "vendor/acme/lib.php": "<?php\n",
        },
      },
    ],
  },
  {
    rule: "PG-HYGIENE-001",
    kind: "positive",
    name: "bower-components",
    expect: ["PG-HYGIENE-001"],
    commits: [{ files: { "bower_components/jquery/jquery.js": "/* jq */\n" } }],
  },
  {
    rule: "PG-HYGIENE-001",
    kind: "negative",
    name: "gitignored-node-modules",
    expect: [],
    commits: [{ files: { ".gitignore": "node_modules/\n", "package.json": "{}\n" } }],
    untracked: { "node_modules/x/index.js": "module.exports = 1;\n" },
  },
  {
    rule: "PG-HYGIENE-001",
    kind: "negative",
    name: "go-module-vendoring",
    expect: [],
    commits: [
      {
        files: {
          "go.mod": "module example.com/app\n\ngo 1.22\n",
          "vendor/modules.txt": "# example.com/dep v1.0.0\n",
          "vendor/example.com/dep/dep.go": "package dep\n",
        },
      },
    ],
  },
  {
    rule: "PG-HYGIENE-001",
    kind: "negative",
    name: "first-party-vendor-module",
    expect: [],
    commits: [{ files: { "src/vendor/service.ts": "export class VendorService {}\n" } }],
  },
  {
    rule: "PG-HYGIENE-001",
    kind: "negative",
    name: "vendor-keep-placeholder",
    expect: [],
    commits: [{ files: { "vendor/.gitkeep": "", Gemfile: "source 'https://rubygems.org'\n" } }],
  },
];
