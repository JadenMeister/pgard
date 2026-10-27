/**
 * Names the Java/Kotlin XSS (PG-XSS-004) and SSRF (PG-SSRF-002) rules recognize: servlet responses
 * and their writers, HTTP clients, URL types, escaping helpers and template engines.
 */

// ------------------------------------------------------------------ XSS: responses

export const RESPONSE_TYPES = new Set([
  "HttpServletResponse",
  "ServletResponse",
  "HttpServletResponseWrapper",
]);
/** A servlet response by its usual name, when its type is not written. */
export const RESPONSE_NAME = /^(?:response|resp|httpResponse|servletResponse)$/;
export const WRITER_GETTERS = new Set(["getWriter", "getOutputStream"]);
export const WRITER_MEMBERS = new Set(["writer", "outputStream"]);
/** Calls on a response writer or stream that put text into the page. */
export const WRITER_METHODS = new Set(["write", "print", "println", "append", "printf", "format"]);
/** Classes that wrap a writer or stream and still write to the response. */
export const WRITER_WRAPPERS = new Set([
  "PrintWriter",
  "PrintStream",
  "BufferedWriter",
  "OutputStreamWriter",
  "BufferedOutputStream",
  "DataOutputStream",
]);
/** Calls on a string that give its bytes or characters (the text is kept). */
export const TEXT_KEEPERS = new Set(["getBytes", "toByteArray", "encodeToByteArray"]);

/** JSON serialisers: their result is known safe text, so it is never reported as HTML output. */
export const SAFE_SERIALIZERS = new Set([
  "writeValueAsString",
  "writeValueAsBytes",
  "toJson",
  "toJSONString",
  "encodeToString",
]);
/** Why an inferred value cannot carry markup (a number, a boolean, a date). */
export const NUMBER_WHY = /number|numeric|boolean|arithmetic|cast to/i;

/** Content types, as words in the expression that sets them. */
export const HTML_CONTENT = /html/i;
export const OTHER_CONTENT =
  /json|xml|plain|octet|csv|javascript|pdf|image|css|stream|yaml|zip|text_event|protobuf/i;

/** Handler annotations on a class that make its String results the response body. */
export const BODY_CLASS_ANNOTATIONS = new Set(["RestController", "ResponseBody"]);

/** Calls on a `Model`, `ModelAndView` or request that make a value available to a template. */
export const MODEL_ADDERS = new Set(["addAttribute", "addObject", "put", "setAttribute"]);
export const MODEL_TYPES = /^(?:Model|ModelMap|ModelAndView|ExtendedModelMap|RedirectAttributes)$/;
export const MODEL_NAME = /^(?:model|modelMap|mav|modelAndView|map|attributes)$/i;

// ------------------------------------------------------------------ escaping

/** Escaping helpers: the result is inferred safe for HTML or URL text, never proven. */
export const ESCAPE_NAME =
  /^(?:escapeHtml\d?|escapeXml\d*|escapeEcmaScript|escapeJavaScript|escapeJava|htmlEscape\w*|javaScriptEscape|forHtml\w*|forXml\w*|forJava\w*|forCss\w*|forUri\w*|encodeFor\w+|sanitize\w*|cleanHtml|clean)$/;
/** Names that escape only on certain classes (`URLEncoder.encode`, `HtmlEscapers.htmlEscaper().escape`). */
export const ESCAPE_CLASSES = new Set([
  "URLEncoder",
  "UriUtils",
  "Encode",
  "ESAPI",
  "HtmlUtils",
  "StringEscapeUtils",
  "HtmlEscapers",
  "Jsoup",
  "Sanitizers",
]);
export const ESCAPE_ANY_CLASS_NAMES = new Set([
  "encode",
  "escape",
  "encodeQueryParam",
  "encodePath",
]);

// ------------------------------------------------------------------ SSRF

export const URL_TYPES = new Set(["URL", "URI"]);
/** Calls on a `URL` that open it. */
export const URL_OPENERS = new Set(["openConnection", "openStream", "getContent"]);
/** Kotlin extensions that read a `URL`. */
export const URL_READERS = new Set(["readText", "readBytes"]);
/** Calls on a `URL`/`URI` or a URL-looking string that give a URL again. */
export const URL_KEEPERS = new Set([
  "toURL",
  "toURI",
  "toExternalForm",
  "toASCIIString",
  "normalize",
  "toString",
  "toHttpUrl",
  "toHttpUrlOrNull",
  "toUri",
  "toUriString",
]);

export const REST_TEMPLATE_UNIQUE = new Set([
  "getForObject",
  "getForEntity",
  "postForObject",
  "postForEntity",
  "postForLocation",
  "patchForObject",
  "headForHeaders",
  "optionsForAllow",
  "exchange",
]);
export const REST_TEMPLATE_SHARED = new Set(["put", "delete", "execute"]);
export const REST_TYPE = /RestTemplate|RestOperations|RestClient/;
export const REST_NAME = /rest/i;

/** Verbs that start a request on a client: `client.get(url)`, `webClient.get().uri(url)`. */
export const HTTP_VERBS = new Set([
  "get",
  "post",
  "put",
  "delete",
  "patch",
  "head",
  "options",
  "method",
  "request",
  "prepareGet",
  "prepareRequest",
  "preparePost",
  "prepareHead",
]);
export const CLIENT_TYPE = /HttpClient|WebClient|RestClient|OkHttpClient|Unirest/;
export const CLIENT_NAME = /client|http|rest|webClient|fetch/i;

export const APACHE_REQUESTS = new Set([
  "HttpGet",
  "HttpPost",
  "HttpPut",
  "HttpDelete",
  "HttpHead",
  "HttpPatch",
  "HttpOptions",
  "HttpTrace",
]);
export const APACHE_BUILDERS = new Set([
  "SimpleRequestBuilder",
  "ClassicRequestBuilder",
  "RequestBuilder",
]);
export const FLUENT_VERBS = new Set([
  "Get",
  "Post",
  "Put",
  "Delete",
  "Head",
  "Patch",
  "Options",
  "Trace",
]);

/** Classes whose static methods read a URL given as the first argument. */
export const URL_CONSUMERS: ReadonlyArray<{ className: string; names: ReadonlySet<string> }> = [
  { className: "ImageIO", names: new Set(["read"]) },
  { className: "IOUtils", names: new Set(["toString", "toByteArray", "copy", "lineIterator"]) },
  { className: "FileUtils", names: new Set(["copyURLToFile", "readLines"]) },
  { className: "Jsoup", names: new Set(["parse"]) },
];

export const HTTP_CLIENT_IMPORTS = {
  jdk: ["java.net.http"],
  spring: [
    "org.springframework.web.client",
    "org.springframework.web.reactive",
    "org.springframework.http.client",
  ],
  okhttp: ["okhttp3", "com.squareup.okhttp"],
  apache: ["org.apache.http", "org.apache.hc"],
  ktor: ["io.ktor.client"],
  other: ["kong.unirest", "com.mashape.unirest", "org.jsoup", "retrofit2", "feign"],
} as const;

/** Text of a skipped code form that makes it matter: a call of the web rules. */
export const WEB_CALL_TEXT =
  /\b(?:openConnection|openStream|getWriter|getOutputStream|getForObject|getForEntity|postForObject|postForEntity|exchange|HttpGet|HttpPost|HttpPut|HttpDelete|HttpRequest|WebClient|RestClient|respondText|HttpUrl|Jsoup|Unirest)\b/;

// ------------------------------------------------------------------ unsupported engines

/** Template engines whose templates the XSS rule does not read. */
export const UNSUPPORTED_TEMPLATE_LIBRARIES: ReadonlyArray<{ prefix: string; label: string }> = [
  { prefix: "freemarker", label: "FreeMarker" },
  { prefix: "org.springframework.web.servlet.view.freemarker", label: "FreeMarker" },
  { prefix: "org.apache.velocity", label: "Velocity" },
  { prefix: "org.springframework.web.servlet.view.velocity", label: "Velocity" },
  { prefix: "com.mitchellbosecke.pebble", label: "Pebble" },
  { prefix: "io.pebbletemplates", label: "Pebble" },
  { prefix: "com.github.mustachejava", label: "Mustache" },
  { prefix: "com.samskivert.mustache", label: "Mustache" },
  { prefix: "gg.jte", label: "JTE" },
];

/** Template file extensions per engine that the XSS rule reads or reports as not analyzed. */
export const TEMPLATE_ENGINES: Record<string, string> = {
  ".ftl": "FreeMarker",
  ".ftlh": "FreeMarker",
  ".ftlx": "FreeMarker",
  ".vm": "Velocity",
  ".vtl": "Velocity",
  ".mustache": "Mustache",
  ".peb": "Pebble",
  ".pebble": "Pebble",
  ".jte": "JTE",
};

/** Reflection: a call made through it is not followed. */
export const REFLECTION_TEXT =
  /\b(?:Class\.forName|getDeclaredMethod|getMethod|MethodHandles\.lookup|Proxy\.newProxyInstance)\s*\(|::class\.java\.get(?:Declared)?Method\b/;
