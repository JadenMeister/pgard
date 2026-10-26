// Web corpus: each case describes one loopback HTTP server the runner starts on 127.0.0.1 and
// scans with scanLocalWeb. Every case is evaluated against all 13 web rules, so a "hardened"
// case is a true negative for every rule at once and each single-defect case is a true positive
// for one rule and a true negative for the rest.
//
// A case: { name, expect: [rule ids], known?: [{ type: "miss"|"fp", rule, reason }],
//           headers?, cookies?, cors?, routes?, rootBody? }
// `headers` are merged over HARDENED (a null value removes a header). `cors(origin)` returns extra
// headers for a request that carries an Origin. `routes` maps a path to { status, headers, body }.

export const WEB_RULE_IDS_EXPECTED = Array.from(
  { length: 13 },
  (_, index) => `PG-WEB-${String(index + 1).padStart(3, "0")}`,
);

export const HARDENED = {
  "content-type": "text/html; charset=utf-8",
  "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
  "x-content-type-options": "nosniff",
  "referrer-policy": "no-referrer",
};

const SECURE_COOKIE = "sid=opaque; Path=/; HttpOnly; Secure; SameSite=Lax";

export const WEB_CASES = [
  { name: "hardened-baseline", expect: [] },
  {
    name: "hardened-with-secure-cookie",
    expect: [],
    cookies: [SECURE_COOKIE],
  },
  {
    name: "xfo-instead-of-csp-frame-ancestors",
    expect: [],
    headers: {
      "content-security-policy": "default-src 'self'",
      "x-frame-options": "SAMEORIGIN",
    },
  },
  {
    name: "server-header-without-version",
    expect: [],
    headers: { server: "nginx", "x-powered-by": "Express" },
  },
  {
    name: "spa-fallback-returns-html-for-every-path",
    expect: [],
    fallbackHtml: true,
  },
  {
    name: "dotfiles-return-404",
    expect: [],
    routes: {
      "/.env": { status: 404, body: "not found" },
      "/.git/HEAD": { status: 404, body: "not found" },
    },
  },
  {
    name: "cors-specific-origin-with-credentials",
    expect: [],
    cors: () => ({
      "access-control-allow-origin": "https://app.example.com",
      "access-control-allow-credentials": "true",
    }),
  },
  {
    name: "cors-wildcard-without-credentials",
    expect: [],
    cors: () => ({ "access-control-allow-origin": "*" }),
  },
  {
    name: "cors-reflected-origin-without-credentials",
    expect: [],
    cors: (origin) => ({ "access-control-allow-origin": origin }),
  },
  {
    name: "env-path-plain-text-without-assignments",
    expect: [],
    routes: { "/.env": { status: 200, headers: { "content-type": "text/plain" }, body: "nope\n" } },
  },
  {
    name: "git-head-path-returns-html-page",
    expect: [],
    routes: {
      "/.git/HEAD": {
        status: 200,
        headers: { "content-type": "text/html" },
        body: "<title>Home</title><p>ref: refs/heads/main</p>",
      },
    },
  },
  {
    name: "index-of-text-in-body-not-title",
    expect: [],
    rootBody: '<title>Docs</title><p>Index of / is a phrase</p><a href="/files/">files</a>',
    routes: {
      "/files/": {
        status: 200,
        headers: { "content-type": "text/html" },
        body: "<title>Files</title><p>Index of /files/</p>",
      },
    },
  },
  {
    name: "redirect-root-to-offsite",
    expect: [],
    rootRedirect: true,
  },

  // ---- headers ----
  {
    name: "no-csp",
    expect: ["PG-WEB-001"],
    headers: { "content-security-policy": null, "x-frame-options": "DENY" },
  },
  {
    name: "empty-csp",
    expect: ["PG-WEB-001", "PG-WEB-002"],
    headers: { "content-security-policy": " " },
  },
  {
    name: "csp-without-frame-protection",
    expect: ["PG-WEB-002"],
    headers: { "content-security-policy": "default-src 'self'" },
  },
  {
    name: "xfo-allow-from-is-not-protection",
    expect: ["PG-WEB-002"],
    headers: {
      "content-security-policy": "default-src 'self'",
      "x-frame-options": "ALLOW-FROM https://a.example",
    },
  },
  {
    name: "no-nosniff",
    expect: ["PG-WEB-003"],
    headers: { "x-content-type-options": null },
  },
  {
    name: "nosniff-wrong-value",
    expect: ["PG-WEB-003"],
    headers: { "x-content-type-options": "sniff" },
  },
  {
    name: "no-referrer-policy",
    expect: ["PG-WEB-004"],
    headers: { "referrer-policy": null },
  },
  {
    name: "bare-express-defaults",
    expect: ["PG-WEB-001", "PG-WEB-002", "PG-WEB-003", "PG-WEB-004"],
    headers: {
      "content-security-policy": null,
      "x-content-type-options": null,
      "referrer-policy": null,
    },
  },

  {
    name: "no-referrer-policy-and-nosniff-values",
    expect: ["PG-WEB-004"],
    headers: { "referrer-policy": null, "x-content-type-options": "NOSNIFF" },
  },
  {
    name: "nosniff-and-referrer-missing",
    expect: ["PG-WEB-003", "PG-WEB-004"],
    headers: { "x-content-type-options": null, "referrer-policy": null },
  },

  // ---- cookies ----
  {
    name: "cookie-bare",
    expect: ["PG-WEB-005", "PG-WEB-006", "PG-WEB-007"],
    cookies: ["sid=opaque; Path=/"],
  },
  {
    name: "cookie-missing-httponly",
    expect: ["PG-WEB-005"],
    cookies: ["sid=opaque; Path=/; Secure; SameSite=Lax"],
  },
  {
    name: "cookie-missing-samesite",
    expect: ["PG-WEB-006"],
    cookies: ["sid=opaque; Path=/; HttpOnly; Secure"],
  },
  {
    name: "cookie-missing-secure",
    expect: ["PG-WEB-007"],
    cookies: ["sid=opaque; Path=/; HttpOnly; SameSite=Strict"],
  },
  {
    name: "cookie-localhost-style-missing-secure-and-samesite",
    expect: ["PG-WEB-006", "PG-WEB-007"],
    cookies: ["connect.sid=opaque; Path=/; HttpOnly"],
  },
  {
    name: "cookie-samesite-none-counts-as-set",
    expect: [],
    cookies: ["sid=opaque; Path=/; HttpOnly; Secure; SameSite=None"],
  },
  {
    name: "two-cookies-one-weak",
    expect: ["PG-WEB-005", "PG-WEB-006"],
    cookies: [SECURE_COOKIE, "theme=dark; Path=/; Secure"],
  },
  {
    name: "cookie-flags-case-insensitive",
    expect: [],
    cookies: ["sid=opaque; path=/; HTTPONLY; SECURE; samesite=lax"],
  },

  // ---- CORS ----
  {
    name: "cors-wildcard-with-credentials",
    expect: ["PG-WEB-008"],
    cors: () => ({
      "access-control-allow-origin": "*",
      "access-control-allow-credentials": "true",
    }),
  },
  {
    name: "cors-reflected-origin-with-credentials",
    expect: ["PG-WEB-009"],
    cors: (origin) => ({
      "access-control-allow-origin": origin,
      "access-control-allow-credentials": "true",
    }),
  },
  {
    name: "cors-wildcard-credentials-mixed-case",
    expect: ["PG-WEB-008"],
    cors: () => ({
      "access-control-allow-origin": "*",
      "access-control-allow-credentials": "True",
    }),
  },
  {
    name: "cors-wildcard-credentials-and-no-csp",
    expect: ["PG-WEB-001", "PG-WEB-008"],
    headers: { "content-security-policy": null, "x-frame-options": "DENY" },
    cors: () => ({
      "access-control-allow-origin": "*",
      "access-control-allow-credentials": "true",
    }),
  },
  {
    name: "cors-reflected-origin-credentials-on-weak-cookie",
    expect: ["PG-WEB-005", "PG-WEB-006", "PG-WEB-007", "PG-WEB-009"],
    cookies: ["sid=opaque; Path=/"],
    cors: (origin) => ({
      "access-control-allow-origin": origin,
      "access-control-allow-credentials": "true",
    }),
  },
  {
    name: "cors-null-origin-with-credentials",
    expect: ["PG-WEB-009"],
    known: [
      {
        type: "miss",
        rule: "PG-WEB-009",
        reason:
          "the probe only sends one unrelated origin, so a server that trusts the literal origin null is not detected",
      },
    ],
    // Truly vulnerable (it trusts Origin: null) but the probe never sends that origin.
    cors: (origin) =>
      origin === "null"
        ? { "access-control-allow-origin": "null", "access-control-allow-credentials": "true" }
        : {},
  },

  // ---- disclosure ----
  {
    name: "server-version",
    expect: ["PG-WEB-010"],
    headers: { server: "nginx/1.25.3" },
  },
  {
    name: "powered-by-version",
    expect: ["PG-WEB-010"],
    headers: { "x-powered-by": "PHP/8.2.12" },
  },
  {
    name: "server-apache-version",
    expect: ["PG-WEB-010"],
    headers: { server: "Apache/2.4.58 (Unix) OpenSSL/3.0.2" },
  },
  {
    name: "server-version-with-other-defects",
    expect: ["PG-WEB-001", "PG-WEB-010"],
    headers: {
      server: "Werkzeug/3.0.1 Python/3.12.1",
      "content-security-policy": null,
      "x-frame-options": "DENY",
    },
  },

  // ---- directory listing ----
  {
    name: "listing-apache-style",
    expect: ["PG-WEB-011"],
    rootBody: '<title>Home</title><a href="/files/">files</a>',
    routes: {
      "/files/": {
        status: 200,
        headers: { "content-type": "text/html" },
        body: "<html><head><title>Index of /files/</title></head><body><h1>Index of /files/</h1></body></html>",
      },
    },
  },
  {
    name: "listing-python-http-server",
    expect: ["PG-WEB-011"],
    rootBody: '<title>Home</title><a href="/pub/">pub</a>',
    routes: {
      "/pub/": {
        status: 200,
        headers: { "content-type": "text/html" },
        body: "<title>Directory listing for /pub/</title><h1>Directory listing for /pub/</h1>",
      },
    },
  },
  {
    name: "listing-lowercase-title",
    expect: ["PG-WEB-011"],
    rootBody: '<title>Home</title><a href="/uploads/">uploads</a>',
    routes: {
      "/uploads/": {
        status: 200,
        headers: { "content-type": "text/html" },
        body: "<TITLE>index of /uploads/</TITLE>",
      },
    },
  },
  {
    name: "listing-nested-link",
    expect: ["PG-WEB-011"],
    rootBody: '<title>Home</title><a href="/a/">a</a>',
    routes: {
      "/a/": {
        status: 200,
        headers: { "content-type": "text/html" },
        body: '<title>Section</title><a href="/a/b/">b</a>',
      },
      "/a/b/": {
        status: 200,
        headers: { "content-type": "text/html" },
        body: "<title>Index of /a/b/</title>",
      },
    },
  },

  // ---- exposure ----
  {
    name: "env-served",
    expect: ["PG-WEB-012"],
    routes: {
      "/.env": {
        status: 200,
        headers: { "content-type": "text/plain" },
        body: "APP_KEY=base64:placeholder\nDEBUG=true\n",
      },
    },
  },
  {
    name: "env-served-with-export",
    expect: ["PG-WEB-012"],
    routes: {
      "/.env": {
        status: 200,
        headers: { "content-type": "text/plain" },
        body: "export DB_HOST=localhost\n",
      },
    },
  },
  {
    name: "env-served-as-octet-stream",
    expect: ["PG-WEB-012"],
    routes: {
      "/.env": {
        status: 200,
        headers: { "content-type": "application/octet-stream" },
        body: "A=1\nB=2\n",
      },
    },
  },
  {
    name: "env-served-no-content-type",
    expect: ["PG-WEB-012"],
    routes: { "/.env": { status: 200, headers: {}, body: "SECRET_TOKEN=abc\n" } },
  },
  {
    name: "git-head-ref",
    expect: ["PG-WEB-013"],
    routes: {
      "/.git/HEAD": {
        status: 200,
        headers: { "content-type": "text/plain" },
        body: "ref: refs/heads/main\n",
      },
    },
  },
  {
    name: "git-head-detached-sha1",
    expect: ["PG-WEB-013"],
    routes: {
      "/.git/HEAD": {
        status: 200,
        headers: { "content-type": "text/plain" },
        body: "0123456789abcdef0123456789abcdef01234567\n",
      },
    },
  },
  {
    name: "git-head-detached-sha256",
    expect: ["PG-WEB-013"],
    routes: {
      "/.git/HEAD": {
        status: 200,
        headers: { "content-type": "text/plain" },
        body: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n",
      },
    },
  },
  {
    name: "git-head-and-env-both",
    expect: ["PG-WEB-012", "PG-WEB-013"],
    routes: {
      "/.env": { status: 200, headers: { "content-type": "text/plain" }, body: "K=v\n" },
      "/.git/HEAD": {
        status: 200,
        headers: { "content-type": "text/plain" },
        body: "ref: refs/heads/dev\n",
      },
    },
  },
];
