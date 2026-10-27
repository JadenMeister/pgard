/** Names the Java/Kotlin SQL rule recognizes: sinks, sources, coercions and guards. */

/** Annotations whose parameter comes from the HTTP request. */
export const SOURCE_ANNOTATIONS = new Set([
  "RequestParam",
  "PathVariable",
  "RequestBody",
  "RequestHeader",
  "CookieValue",
  "ModelAttribute",
  "RequestPart",
  "MatrixVariable",
  "QueryParam",
  "PathParam",
  "FormParam",
  "HeaderParam",
  "CookieParam",
  "MatrixParam",
  "BeanParam",
  "QueryValue",
]);

/** Method annotations that make a method an HTTP handler (parameters bind from the request). */
export const HANDLER_ANNOTATIONS = new Set([
  "RequestMapping",
  "GetMapping",
  "PostMapping",
  "PutMapping",
  "DeleteMapping",
  "PatchMapping",
  "GET",
  "POST",
  "PUT",
  "DELETE",
  "PATCH",
  "Get",
  "Post",
  "Put",
  "Delete",
  "Patch",
]);

/** Parameter types of a handler that are not request input. */
export const NON_INPUT_TYPES = new Set([
  "Model",
  "ModelMap",
  "ModelAndView",
  "Principal",
  "Authentication",
  "Locale",
  "BindingResult",
  "Errors",
  "Pageable",
  "HttpSession",
  "HttpServletResponse",
  "ServletResponse",
  "UriComponentsBuilder",
  "RedirectAttributes",
  "SessionStatus",
  "InputStream",
  "OutputStream",
  "Reader",
  "Writer",
  "TimeZone",
  "ZoneId",
  "HttpMethod",
  "HttpEntity",
  "Sort",
]);

export const REQUEST_TYPES = new Set([
  "HttpServletRequest",
  "ServletRequest",
  "HttpServletRequestWrapper",
  "WebRequest",
  "NativeWebRequest",
  "ServerHttpRequest",
  "ServerWebExchange",
  "ServerRequest",
  "ApplicationCall",
  "ApplicationRequest",
  "RoutingCall",
  "RoutingContext",
  "PipelineContext",
]);

/** A request object by its usual name. */
export const REQUEST_NAME = /^(?:req|request|httpRequest|servletRequest|call|exchange)$/;

/** Members of a request object that hold request input. */
export const REQUEST_SOURCES = new Set([
  "getParameter",
  "getParameterValues",
  "getParameterMap",
  "getParameterNames",
  "getHeader",
  "getHeaders",
  "getHeaderNames",
  "getQueryString",
  "getPathInfo",
  "getRequestURI",
  "getRequestURL",
  "getServletPath",
  "getCookies",
  "getInputStream",
  "getReader",
  "getPart",
  "getParts",
  "getQueryParams",
  "queryParam",
  "queryParams",
  "pathVariable",
  "pathVariables",
  "bodyToMono",
  "bodyToFlux",
  "formData",
  "multipartData",
  "parameters",
  "queryParameters",
  "pathParameters",
  "rawQueryParameters",
  "headers",
  "cookies",
  "uri",
  "path",
  "receive",
  "receiveNullable",
  "receiveText",
  "receiveParameters",
  "receiveStream",
  "receiveChannel",
  "param",
  "params",
  "header",
]);
/** Members of a request object that give the request object again. */
export const REQUEST_SELF = new Set(["request", "getRequest", "getNativeRequest"]);

/** Classes whose static members parse or build a typed (numeric, date, UUID) value. */
export const COERCING_CLASSES = new Set([
  "Integer",
  "Long",
  "Short",
  "Byte",
  "Double",
  "Float",
  "Boolean",
  "BigDecimal",
  "BigInteger",
  "Math",
  "UUID",
  "LocalDate",
  "LocalDateTime",
  "LocalTime",
  "Instant",
  "Duration",
  "OffsetDateTime",
  "ZonedDateTime",
  "Number",
]);
/** Types that cannot carry SQL text. `char` and `Character` are not here: one `'` is enough. */
export const NUMERIC_TYPES = new Set([
  "int",
  "long",
  "short",
  "byte",
  "double",
  "float",
  "boolean",
  "Integer",
  "Long",
  "Short",
  "Byte",
  "Double",
  "Float",
  "Boolean",
  "BigDecimal",
  "BigInteger",
  "Int",
  "UInt",
  "ULong",
  "UShort",
  "UByte",
  "Number",
  "UUID",
  "LocalDate",
  "LocalDateTime",
  "Instant",
]);
/** Instance methods and Kotlin conversions whose result is a number or boolean. */
export const NUMERIC_RESULTS = new Set([
  "toInt",
  "toLong",
  "toShort",
  "toByte",
  "toDouble",
  "toFloat",
  "toBoolean",
  "toBigDecimal",
  "toBigInteger",
  "toIntOrNull",
  "toLongOrNull",
  "toDoubleOrNull",
  "toFloatOrNull",
  "toBooleanStrict",
  "toUInt",
  "toULong",
  "intValue",
  "longValue",
  "doubleValue",
  "floatValue",
  "shortValue",
  "byteValue",
  "booleanValue",
  "ordinal",
  "length",
  "size",
  "count",
  "hashCode",
  "isEmpty",
  "isBlank",
  "isNotEmpty",
  "isNotBlank",
  "indexOf",
  "lastIndexOf",
  "compareTo",
  "signum",
]);
export const NUMERIC_MEMBERS = new Set(["length", "size", "ordinal", "lastIndex", "indices"]);

/** String methods whose result is made of the receiver and the arguments. */
export const PASS_THROUGH = new Set([
  "trim",
  "strip",
  "stripLeading",
  "stripTrailing",
  "toLowerCase",
  "toUpperCase",
  "lowercase",
  "uppercase",
  "toString",
  "intern",
  "substring",
  "substringBefore",
  "substringAfter",
  "substringBeforeLast",
  "substringAfterLast",
  "replace",
  "replaceAll",
  "replaceFirst",
  "concat",
  "plus",
  "repeat",
  "trimIndent",
  "trimMargin",
  "orEmpty",
  "ifEmpty",
  "ifBlank",
  "take",
  "drop",
  "removePrefix",
  "removeSuffix",
  "padStart",
  "padEnd",
  "capitalize",
  "decapitalize",
  "valueOf",
  "copyValueOf",
  "join",
  "joinToString",
  "requireNotNull",
  "checkNotNull",
  "requireNonNull",
  "orElse",
  "orElseGet",
  "orElseThrow",
  "toCharArray",
  "chars",
  "stream",
  "collect",
  "joining",
  "unmodifiableList",
  "unmodifiableSet",
  "unmodifiableMap",
]);
/** Of those, the ones that put several values into one string. */
export const COMPOSING = new Set(["concat", "plus", "join", "joinToString", "joining"]);

export const LOOKUPS = new Set([
  "get",
  "getOrDefault",
  "getOrElse",
  "getOrNull",
  "getValue",
  "getOrPut",
  "firstOrNull",
  "first",
  "last",
  "elementAt",
]);

export const COLLECTION_FACTORIES = new Set([
  "of",
  "asList",
  "listOf",
  "setOf",
  "mapOf",
  "arrayOf",
  "hashMapOf",
  "hashSetOf",
  "linkedMapOf",
  "linkedSetOf",
  "sortedSetOf",
  "sortedMapOf",
  "ofEntries",
  "entry",
  "singletonList",
  "singleton",
  "copyOf",
  "listOfNotNull",
  "immutableListOf",
  "persistentListOf",
]);

export const BUILDER_TYPES = new Set(["StringBuilder", "StringBuffer", "StringJoiner"]);
export const BUILDER_ADDERS = new Set([
  "append",
  "appendLine",
  "insert",
  "add",
  "prepend",
  "replace",
]);

/** JDBC calls that take SQL text as the first argument; unambiguous by name. */
export const JDBC_SINKS = new Set([
  "executeQuery",
  "executeUpdate",
  "executeLargeUpdate",
  "addBatch",
  "prepareStatement",
  "prepareCall",
  "nativeSQL",
]);
/** Calls that take SQL text but share their name with unrelated methods: they need a SQL receiver. */
export const GENERIC_SINKS = new Set([
  "query",
  "queryForObject",
  "queryForList",
  "queryForMap",
  "queryForRowSet",
  "queryForStream",
  "queryForInt",
  "queryForLong",
  "update",
  "batchUpdate",
  "execute",
  "sql",
]);
/** JPA/Hibernate query factories. */
export const ORM_SINKS = new Set([
  "createQuery",
  "createNativeQuery",
  "createSQLQuery",
  "createNativeMutationQuery",
  "createSelectionQuery",
  "createMutationQuery",
]);

export const SQL_IMPORT_PREFIXES = [
  "java.sql",
  "javax.sql",
  "org.springframework.jdbc",
  "org.springframework.data",
  "org.springframework.orm",
  "org.springframework.r2dbc",
  "javax.persistence",
  "jakarta.persistence",
  "org.hibernate",
  "org.apache.ibatis",
  "org.mybatis",
  "groovy.sql",
  "io.r2dbc",
  "org.jdbi",
  "org.sql2o",
];

export const SQL_TEXT =
  /\b(?:select|insert\s+into|update|delete\s+from|from|where|values|union|order\s+by|group\s+by|join|having|limit|call)\b/i;
export const SQL_TYPE =
  /(?:JdbcTemplate|JdbcOperations|NamedParameterJdbc|JdbcClient|Statement|Connection|EntityManager|Session|SqlSession|DatabaseClient|Jdbi|Handle|Sql2o)/;
export const SQL_NAME =
  /(?:jdbc|template|stmt|statement|conn|connection|entityManager|^em$|session|sqlSession|database|^db$|^st$)/i;
/** A call on the result of these is on a JDBC object: `conn.createStatement().execute(q)`. */
export const SQL_PRODUCERS = new Set([
  "createStatement",
  "prepareStatement",
  "prepareCall",
  "getConnection",
  "getJdbcTemplate",
  "getJdbcOperations",
  "getEntityManager",
  "getCurrentSession",
  "openSession",
  "getSession",
  "getNamedParameterJdbcTemplate",
]);

/** Conditions that name an allowlist or validator. */
export const VALIDATOR_NAME = /allow|valid|whitelist|permit|safe|legit|known|support|sanitiz/i;

/** Text of a skipped code form that makes it matter: a call that looks like a SQL call. */
export const SQL_CALL_TEXT =
  /\b(?:executeQuery|executeUpdate|executeLargeUpdate|addBatch|prepareStatement|prepareCall|query\w*|update|batchUpdate|execute|createQuery|createNativeQuery|createSQLQuery|createNativeMutationQuery|createSelectionQuery|createMutationQuery)\s*\(/;

/** Libraries with their own SQL APIs that the rule does not analyze. */
export const UNSUPPORTED_LIBRARIES: ReadonlyArray<{ prefix: string; label: string }> = [
  { prefix: "org.jooq", label: "jOOQ" },
  { prefix: "org.jetbrains.exposed", label: "Exposed" },
  { prefix: "androidx.room", label: "Room" },
];
/** MyBatis annotations that name a class which builds the SQL. */
export const MYBATIS_PROVIDERS = new Set([
  "SelectProvider",
  "InsertProvider",
  "UpdateProvider",
  "DeleteProvider",
]);
