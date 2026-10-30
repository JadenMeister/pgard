// History corpus: each case is a throwaway git repository the runner builds from `commits`.
//
// Nothing here is a real credential. Every secret-looking value is assembled from fragments at
// run time, so no detector (GitHub push protection, secret scanners) sees a whole token in this
// file, and none of the values was ever issued by a provider.
//
// A case: { rule, kind, name, expect: [rule ids], low?: true (negative: its rule must report only at low confidence), known?: [{ type: "miss"|"fp", rule, reason }],
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
  assembled: join("Xk9v", "Lp8W", "z4qR", "t2mN7"),
  bracket: join("Xk9v", "]Lp8", "Wz4q"),
  angle: join("Qw3r", "<Ty7u", "Io9p"),
  paren: join("Zx8c", ")Vb5n", "Mq2w"),
  colon: join("Hj6k", "Lm4n", "Pq2r:"),
  capsWords: join("MY_SUPER", "_SECRET", "_KEY"),
  dbPassword: join("Xq9", "!vR2", "#mT7", "pLw4"),
  pem: join(
    "-----BEGIN ",
    "RSA ",
    "PRIVATE KEY-----\nMIIEowIBAAKCAQEAq7Zt3nXk9pLw4RvB2cYd8Hs1Jf6UeNgA0oTm5VxQzWiKl3Dc\n-----END ",
    "RSA PRIVATE KEY-----\n",
  ),
  urlPassword: join("postgres://app:", "Xq9vR2mT7pLw4", "@db.internal:5432/app"),
};

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
    name: "aws-secret-access-key",
    expect: ["PG-SECRET-002"],
    commits: [{ files: { "config/aws.ini": `aws_secret_access_key = ${FAKE.awsSecret}\n` } }],
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
  // #445: false positives in templates, docs and minified bundles, and real secrets in the same
  // shapes that must still be reported.
  {
    rule: "PG-SECRET-002",
    kind: "negative",
    name: "env-example-placeholder-words",
    expect: [],
    commits: [
      {
        files: {
          ".env.example": [
            "JWT_SECRET=replace-with-a-long-random-secret",
            "SESSION_SECRET=generate-a-strong-session-key",
            "API_KEY=insert-your-api-key-here",
            "DB_PASSWORD=set_me_to_a_password",
            "COOKIE_SECRET=put-your-cookie-secret-here",
            "",
          ].join("\n"),
        },
      },
    ],
  },
  {
    rule: "PG-SECRET-002",
    kind: "negative",
    name: "docs-dictionary-words-example",
    expect: [],
    commits: [
      {
        files: {
          "README.md": 'Configure `api_key = "my-secret-key-value"` in your settings.\n',
          "docs/setup.rst": "client_secret: my-example-secret-word\n",
        },
      },
    ],
  },
  {
    rule: "PG-SECRET-002",
    kind: "negative",
    name: "minified-bundle-member-access",
    expect: [],
    commits: [
      {
        files: {
          "build/static/js/main.js":
            "function f(e,t){return a({password:e.target.value}),(e.password==t.password)||g(e.password==e.pass)||h()}\n",
          "dist/assets/app.js": "x=e.secret===t.secret&&n,y={apiKey:r.config.apikey});\n",
        },
      },
    ],
  },
  {
    rule: "PG-SECRET-001",
    kind: "negative",
    name: "dotenv-generic-lines-folded",
    // One PG-SECRET-001 for the file; its generic lines are not reported one by one.
    expect: ["PG-SECRET-001"],
    commits: [
      { files: { ".env": `DB_PASSWORD=${FAKE.dbPassword}\nSESSION_SECRET=${FAKE.assembled}\n` } },
    ],
  },
  {
    rule: "PG-SECRET-002",
    kind: "positive",
    name: "env-example-real-looking-aws-key",
    expect: ["PG-SECRET-002"],
    commits: [{ files: { ".env.example": `AWS_ACCESS_KEY_ID=${FAKE.aws}\nPORT=3000\n` } }],
  },
  {
    rule: "PG-SECRET-002",
    kind: "positive",
    name: "env-example-high-entropy-password",
    expect: ["PG-SECRET-002"],
    commits: [{ files: { ".env.example": `DB_PASSWORD=${FAKE.assembled}\n` } }],
  },
  {
    rule: "PG-SECRET-002",
    kind: "positive",
    name: "minified-bundle-real-password",
    expect: ["PG-SECRET-002"],
    commits: [
      {
        files: {
          "build/static/js/main.js": `function f(e){return a({password:e.target.value}),b({user:"admin",password:"${FAKE.assembled}"})}\n`,
        },
      },
    ],
  },
  {
    rule: "PG-SECRET-002",
    kind: "positive",
    name: "docs-quoted-mixed-case-value",
    expect: ["PG-SECRET-002"],
    commits: [{ files: { "README.md": `Set \`api_key = "${FAKE.assembled}"\` first.\n` } }],
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
    name: "code-text-in-escaped-string-single-quoted",
    expect: [],
    low: true,
    commits: [
      {
        files: {
          "test/fixture.js":
            "const source = 'const SECRET_PATTERN = /^(secret|token)$/i;\\nlet n = 1;\\n';\n",
        },
      },
    ],
  },
  {
    rule: "PG-SECRET-002",
    kind: "negative",
    name: "codegen-regex-in-double-quoted-string",
    expect: [],
    low: true,
    commits: [
      {
        files: {
          "test/cases.mjs":
            'const src = "const PASSWORD_RE = /^(pass|pwd)$/i;\\nconst x = 1;\\n";\n',
        },
      },
    ],
  },
  {
    rule: "PG-SECRET-002",
    kind: "negative",
    name: "codegen-type-member-in-string",
    expect: [],
    low: true,
    commits: [
      {
        files: {
          "test/gen.ts":
            'const src = "interface C {\\n  apiKey: Record<string, string>;\\n}\\n";\n',
        },
      },
    ],
  },
  {
    rule: "PG-SECRET-002",
    kind: "negative",
    name: "codegen-constant-name-in-string",
    expect: [],
    low: true,
    commits: [
      {
        files: {
          "test/gen.js":
            'const src = "export const SECRET = SECRET_ENV_NAME;\\nuse(SECRET);\\n";\n',
        },
      },
    ],
  },
  {
    rule: "PG-SECRET-002",
    kind: "positive",
    name: "env-text-in-escaped-string",
    expect: ["PG-SECRET-002"],
    commits: [
      {
        files: {
          "scripts/seed.js": `fs.writeFileSync(".env", "PORT=3000\\nDB_PASSWORD=${FAKE.assembled}\\n");\n`,
        },
      },
    ],
  },
  {
    rule: "PG-SECRET-002",
    kind: "positive",
    name: "literal-credential-on-its-own-line",
    expect: ["PG-SECRET-002"],
    commits: [{ files: { "config/service.conf": `DEBUG=1\nAPI_SECRET=${FAKE.assembled}\n` } }],
  },
  {
    rule: "PG-SECRET-002",
    kind: "positive",
    name: "escaped-string-password-with-bracket",
    expect: ["PG-SECRET-002"],
    commits: [
      {
        files: { "scripts/conf.js": `const conf = "user=admin\\npassword=${FAKE.bracket}\\n";\n` },
      },
    ],
  },
  {
    rule: "PG-SECRET-002",
    kind: "positive",
    name: "escaped-string-password-with-angle",
    expect: ["PG-SECRET-002"],
    commits: [
      { files: { "scripts/conf.ts": `const yaml = "db:\\n  password: ${FAKE.angle}\\n";\n` } },
    ],
  },
  {
    rule: "PG-SECRET-002",
    kind: "positive",
    name: "escaped-string-password-with-paren",
    expect: ["PG-SECRET-002"],
    commits: [
      { files: { "src/Db.cs": `var cs = "Server=db;User=sa;Password=${FAKE.paren};\\n";\n` } },
    ],
  },
  {
    rule: "PG-SECRET-002",
    kind: "positive",
    name: "escaped-string-password-ending-colon",
    expect: ["PG-SECRET-002"],
    commits: [{ files: { "scripts/conf.rb": `conf = "user=admin\\npassword=${FAKE.colon}"\n` } }],
  },
  {
    rule: "PG-SECRET-002",
    kind: "positive",
    name: "escape-in-another-string-same-line",
    expect: ["PG-SECRET-002"],
    commits: [
      { files: { "src/app.js": `log("done\\n"); const cfg = "api_key=${FAKE.bracket}";\n` } },
    ],
  },
  {
    rule: "PG-SECRET-002",
    kind: "positive",
    name: "escaped-string-caps-secret-last",
    expect: ["PG-SECRET-002"],
    commits: [
      {
        files: {
          "scripts/seed.js": `write(".env", "PORT=8080\\nJWT_SECRET=${FAKE.capsWords}");\n`,
        },
      },
    ],
  },
  {
    rule: "PG-SECRET-002",
    kind: "positive",
    name: "escaped-string-caps-secret-before-space",
    expect: ["PG-SECRET-002"],
    commits: [
      {
        files: {
          "scripts/run.js": `exec("echo start\\n; ADMIN_PASSWORD=${FAKE.capsWords} node server.js");\n`,
        },
      },
    ],
  },
  {
    rule: "PG-SECRET-002",
    kind: "positive",
    name: "config-file-password-with-literal-backslash-n",
    expect: ["PG-SECRET-002"],
    commits: [{ files: { "config/app.conf": `DB_PASSWORD=Ab3\\nXy9Zk2Lm7Q\n` } }],
  },
  {
    rule: "PG-SECRET-002",
    kind: "positive",
    name: "properties-password-with-literal-backslash-n",
    expect: ["PG-SECRET-002"],
    commits: [{ files: { "app.properties": `db.password=P@s5\\nw0rdXk9vL\n` } }],
  },
  {
    rule: "PG-SECRET-002",
    kind: "positive",
    name: "escaped-backslash-n-inside-string-value",
    expect: ["PG-SECRET-002"],
    commits: [{ files: { "src/f.ts": `const s = "password=Ab3\\\\nXy9Zk2Lm7Q";\n` } }],
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
