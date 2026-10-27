/**
 * Modules whose sanitizing entry points fully suppress an XSS finding, when the call goes through
 * the file's sole, unshadowed, unmodified import binding. A sanitizer found any other way (a local
 * function, a re-export from a local module, a global, a Vue method) is only inferred from its
 * name and keeps a low-confidence finding. Any other method of a trusted module (a config getter,
 * a context filter that escapes only a quote) proves nothing and is reported as usual.
 *
 * `escape-html` is deliberately absent: it escapes only `& < > " '`, so it demotes, never drops.
 */
interface TrustedSanitizer {
  /** Calling the default or namespace import itself sanitizes: `sanitizeHtml(html)`. */
  callable: boolean;
  /** Methods (`DOMPurify.sanitize`) and named exports (`{ filterXSS }`) that sanitize HTML. */
  methods: readonly string[];
}

const TRUSTED_SANITIZERS: Readonly<Record<string, TrustedSanitizer>> = {
  dompurify: { callable: false, methods: ["sanitize"] },
  "isomorphic-dompurify": { callable: false, methods: ["sanitize"] },
  "sanitize-html": { callable: true, methods: [] },
  xss: { callable: true, methods: ["filterXSS", "xss"] },
  "js-xss": { callable: true, methods: ["filterXSS", "xss"] },
  // Only the HTML data context escapes `<`; `inDoubleQuotedAttr`, `inHTMLComment` and the rest
  // escape just the characters of their own context.
  "xss-filters": { callable: false, methods: ["inHTMLData"] },
  insane: { callable: true, methods: [] },
};

export const TRUSTED_SANITIZER_MODULES: ReadonlySet<string> = new Set(
  Object.keys(TRUSTED_SANITIZERS),
);

/** Modules whose default export is the factory `createDOMPurify(window)`. */
export const DOMPURIFY_FACTORY_MODULES: ReadonlySet<string> = new Set(["dompurify"]);

/**
 * Whether a call through a binding of a trusted module sanitizes HTML.
 * `binding`: the default/namespace import (or a `require` result) vs a named import.
 * `shape`: `direct` is `f(x)`, `member` is `f.method(x)`. `name`: the named export or the method.
 */
export function isTrustedSanitizerCall(
  module: string,
  binding: "default" | "named",
  shape: "direct" | "member",
  name: string,
): boolean {
  const entry = Object.hasOwn(TRUSTED_SANITIZERS, module) ? TRUSTED_SANITIZERS[module] : undefined;
  if (!entry) return false;
  if (binding === "default")
    return shape === "direct" ? entry.callable : entry.methods.includes(name);
  return shape === "direct" && entry.methods.includes(name);
}

/** Names that look like a sanitizer; a match without a proven import is inferred only. */
export const SANITIZER_NAME =
  /^(sanitize|sanitizeHtml|purify|escape|escapeHtml|encode|xss|filterXSS|htmlEscape)$/i;
