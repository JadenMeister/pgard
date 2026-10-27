/**
 * Names the PHP SQL injection (PG-SQL-006) and command execution (PG-CMD-004) rules recognize:
 * sinks, request sources, escaping and coercion functions, and validators.
 */

// ------------------------------------------------------------------ request input

/** Superglobals that carry request input (`$_SERVER` is handled by key, see `SERVER_INPUT_KEY`). */
export const REQUEST_SUPERGLOBALS = new Set([
  "$_GET",
  "$_POST",
  "$_REQUEST",
  "$_COOKIE",
  "$_FILES",
]);
/** `$_SERVER` keys that the client controls. */
export const SERVER_INPUT_KEY =
  /^(?:HTTP_|REQUEST_URI$|QUERY_STRING$|PHP_SELF$|PATH_INFO$|PATH_TRANSLATED$|ORIG_PATH_INFO$|PHP_AUTH_)/;
/** Other superglobals: values that were stored earlier or come from the host. */
export const OTHER_SUPERGLOBALS = new Set(["$_SESSION", "$_ENV", "$GLOBALS", "$_SERVER"]);

/** A parameter or property type that is a request object (Laravel, Symfony, PSR-7, CodeIgniter). */
export const REQUEST_TYPE = /(?:^|\\)(?:\w*Request|ServerRequestInterface|IncomingRequest)$/;
/** The names a request object usually has when it comes from a property or a helper. */
export const REQUEST_NAME = /^\$(?:request|req|httpRequest)$/i;
/** Properties of `$this` that hold the request (CodeIgniter `input`, Symfony/Cake `request`). */
export const REQUEST_THIS_PROPS = new Set(["request", "input"]);
/** Properties of a request object that are themselves bags of request input (Symfony). */
export const REQUEST_BAGS = new Set([
  "query",
  "request",
  "headers",
  "cookies",
  "attributes",
  "files",
  "server",
]);
/** Methods of a request object that do not return request input. */
export const REQUEST_BENIGN_METHODS = new Set([
  "user",
  "ip",
  "ips",
  "method",
  "ismethod",
  "ismethodsafe",
  "is",
  "ajax",
  "pjax",
  "secure",
  "wantsjson",
  "expectsjson",
  "acceptsjson",
  "hasheader",
  "has",
  "hasany",
  "filled",
  "isnotfilled",
  "missing",
  "exists",
  "boolean",
  "hasfile",
  "isxmlhttprequest",
  "session",
  "hassession",
  "setlocale",
  "setmethod",
  "setuserresolver",
  "merge",
  "replace",
  "schemeandhttphost",
  "getmethod",
  "getscheme",
  "ishttps",
  "isjson",
  "isfromtrustedproxy",
  "getclientip",
  "getlocale",
  "getdefaultlocale",
  "getsession",
]);
/** Static calls on the request facade that return request input. */
export const REQUEST_FACADE_METHODS = new Set([
  "input",
  "get",
  "post",
  "query",
  "all",
  "only",
  "except",
  "cookie",
  "header",
  "json",
  "route",
  "file",
  "getcontent",
  "string",
  "str",
]);
/** Functions that return request input. */
export const REQUEST_FUNCTIONS = new Set([
  "filter_input",
  "filter_input_array",
  "getallheaders",
  "apache_request_headers",
]);

// ------------------------------------------------------------------ SQL sinks

/** Function sinks: the position of the SQL text. */
export const SQL_FUNCTIONS: Readonly<Record<string, number>> = {
  mysqli_query: 1,
  mysqli_real_query: 1,
  mysqli_multi_query: 1,
  mysql_query: 0,
  mysql_unbuffered_query: 0,
  pg_query: 1,
  pg_send_query: 1,
  sqlite_query: 1,
};
/** `pg_query($sql)` is also valid with the SQL text first. */
export const SQL_FUNCTIONS_FIRST_IF_ONE_ARG = new Set(["pg_query"]);

/** Methods that run SQL on any object that looks like a database handle or has SQL-looking text. */
export const SQL_HANDLE_METHODS = new Set([
  "query",
  "exec",
  "prepare",
  "real_query",
  "multi_query",
  "executequery",
  "executestatement",
  "executeupdate",
  "fetchassociative",
  "fetchallassociative",
  "fetchone",
  "fetchfirstcolumn",
  "fetchnumeric",
  "fetchallnumeric",
  "fetchallkeyvalue",
]);
/** Methods that are SQL on a handle whose type says it is one, or on the `DB` facade. */
export const SQL_FACADE_METHODS = new Set([
  "select",
  "selectone",
  "scalar",
  "statement",
  "unprepared",
  "insert",
  "update",
  "delete",
  "affectingstatement",
  "cursor",
]);
/** Doctrine methods whose name alone says the argument is a query (any receiver). */
export const SQL_DISTINCT_METHODS = new Set(["createquery", "createnativequery"]);
/** Laravel query builder methods that take a raw SQL fragment first. */
export const SQL_RAW_METHODS = new Set([
  "whereraw",
  "orwhereraw",
  "selectraw",
  "orderbyraw",
  "havingraw",
  "orhavingraw",
  "groupbyraw",
  "fromraw",
]);

/** The last name of a receiver (`$this->db` -> `db`, `$readConn` -> `readconn`) looks like a handle. */
export const DB_HANDLE_NAME =
  /(?:pdo|mysqli|conn|connection|dbh?|database|link|wpdb|dbal|entitymanager|^em)$/i;
/** A parameter or property type that is a database handle. */
export const DB_TYPE =
  /(?:PDO|mysqli|Connection|EntityManager|DatabaseManager|DatabaseInterface|DBAL|ConnectionInterface)/;
/** Classes whose `new` makes a database handle. */
export const DB_CLASSES = new Set(["PDO", "mysqli"]);

export const SQL_TEXT =
  /\b(?:select|insert\s+into|update|delete\s+from|from|where|values|union|order\s+by|group\s+by|join|having|limit|call)\b/i;

// ------------------------------------------------------------------ command sinks

/** Functions that run a command string through a shell, with the position of the command. */
export const COMMAND_FUNCTIONS = new Set([
  "exec",
  "system",
  "shell_exec",
  "passthru",
  "popen",
  "proc_open",
  "pcntl_exec",
]);

// ------------------------------------------------------------------ values

/** Functions that make a number or a boolean from anything: fixed safe, like a cast. */
export const FIXED_FUNCTIONS = new Set(["intval", "floatval", "doubleval", "boolval"]);
/** Functions whose result is a number, a digest or a date: demoted, not silent. */
export const NUMBER_FUNCTIONS = new Set([
  "abs",
  "round",
  "floor",
  "ceil",
  "intdiv",
  "count",
  "sizeof",
  "strlen",
  "mb_strlen",
  "time",
  "microtime",
  "hrtime",
  "mt_rand",
  "rand",
  "random_int",
  "crc32",
  "uniqid",
  "md5",
  "sha1",
  "hash",
  "bin2hex",
  "date",
  "gmdate",
  "strtotime",
  "mktime",
  "max",
  "min",
  "array_sum",
  "ord",
  "strpos",
  "stripos",
  "mb_strpos",
]);
/** Encoders that remove quotes and spaces; demoted, not silent. */
export const ENCODER_FUNCTIONS = new Set([
  "urlencode",
  "rawurlencode",
  "base64_encode",
  "json_encode",
  "http_build_query",
]);
/** Functions that return their text argument(s), changed in a way that does not make it safe. */
export const PASS_THROUGH_FUNCTIONS = new Set([
  "trim",
  "ltrim",
  "rtrim",
  "chop",
  "strtolower",
  "strtoupper",
  "mb_strtolower",
  "mb_strtoupper",
  "ucfirst",
  "ucwords",
  "lcfirst",
  "substr",
  "mb_substr",
  "str_pad",
  "str_repeat",
  "strrev",
  "strval",
  "stripslashes",
  "htmlspecialchars",
  "htmlspecialchars_decode",
  "htmlentities",
  "html_entity_decode",
  "strip_tags",
  "urldecode",
  "rawurldecode",
  "base64_decode",
  "nl2br",
  "wordwrap",
  "str_replace",
  "str_ireplace",
  "preg_replace",
  "preg_replace_callback",
  "substr_replace",
  "strtr",
  "iconv",
  "mb_convert_encoding",
  "mb_convert_case",
  "utf8_encode",
  "utf8_decode",
  "sanitize_text_field",
  "esc_html",
  "esc_attr",
  "e",
  "__",
  "array_map",
  "array_filter",
  "array_merge",
  "array_values",
  "array_keys",
  "array_unique",
  "array_slice",
  "array_reverse",
  "array_column",
  "array_combine",
  "array_pop",
  "array_shift",
  "array_flip",
  "array_diff",
  "array_intersect",
  "array_replace",
  "explode",
  "str_split",
  "mb_str_split",
  "preg_split",
  "end",
  "reset",
  "current",
  "next",
  "prev",
  "key",
  "compact",
  "func_get_args",
  "func_get_arg",
  "array_merge_recursive",
  "iterator_to_array",
  "json_decode",
  "unserialize",
]);
/** Functions whose result is a boolean. */
export const BOOLEAN_FUNCTIONS = new Set([
  "isset",
  "empty",
  "is_null",
  "is_string",
  "is_array",
  "is_object",
  "is_callable",
  "is_numeric",
  "is_int",
  "is_integer",
  "is_long",
  "is_float",
  "is_bool",
  "in_array",
  "array_key_exists",
  "key_exists",
  "str_contains",
  "str_starts_with",
  "str_ends_with",
  "preg_match",
  "preg_match_all",
  "ctype_digit",
  "ctype_alnum",
  "ctype_alpha",
  "ctype_xdigit",
  "ctype_upper",
  "ctype_lower",
  "ctype_space",
  "ctype_punct",
  "file_exists",
  "is_file",
  "is_dir",
  "function_exists",
  "class_exists",
  "method_exists",
  "property_exists",
  "defined",
  "headers_sent",
  "checkdate",
  "password_verify",
  "hash_equals",
  "version_compare",
  "mysqli_connect_errno",
  "mysqli_ping",
  "is_resource",
  "is_scalar",
  "is_iterable",
  "is_countable",
  "is_a",
  "is_subclass_of",
]);

/** Escaping that is not enough on its own (identifiers, unquoted numbers, shell fragments). */
export const ESCAPE_FUNCTIONS: Readonly<Record<string, string>> = {
  mysqli_real_escape_string: "escaped with mysqli_real_escape_string",
  mysql_real_escape_string: "escaped with mysql_real_escape_string",
  mysqli_escape_string: "escaped with mysqli_escape_string",
  mysql_escape_string: "escaped with mysql_escape_string",
  pg_escape_string: "escaped with pg_escape_string",
  pg_escape_literal: "escaped with pg_escape_literal",
  pg_escape_identifier: "escaped with pg_escape_identifier",
  sqlite_escape_string: "escaped with sqlite_escape_string",
  addslashes: "escaped with addslashes",
  esc_sql: "escaped with esc_sql",
  escapeshellarg: "escaped with escapeshellarg",
  escapeshellcmd: "escaped with escapeshellcmd",
};
/** Methods that escape a value (`$mysqli->real_escape_string`, `$pdo->quote`). */
export const ESCAPE_METHODS: Readonly<Record<string, string>> = {
  real_escape_string: "escaped with real_escape_string",
  escape_string: "escaped with escape_string",
  quote: "quoted with quote()",
  escapestring: "escaped with escapeString",
};

/** Validator-style names: a call with the variable as its argument, in a guard. */
export const VALIDATOR_NAME = /^(?:is_?valid|validate|check_?|allowed|whitelist|assert_?)/i;
export const CTYPE_FUNCTIONS = new Set([
  "ctype_digit",
  "ctype_alnum",
  "ctype_alpha",
  "ctype_xdigit",
  "is_numeric",
  "is_int",
  "is_integer",
  "is_long",
  "is_float",
  "is_bool",
]);
/** `filter_var` filters that only let numbers, booleans and addresses through. */
export const FILTER_NUMERIC = /^FILTER_VALIDATE_(?:INT|FLOAT|BOOL|BOOLEAN|IP|MAC)$/;

/** Calls that end the code that follows them (like `exit`). */
export const EXIT_FUNCTIONS = new Set(["exit", "die", "abort", "abort_if", "abort_unless"]);

// ------------------------------------------------------------------ unsupported libraries

/**
 * Imported or used libraries with their own SQL or process APIs that are not followed. A match
 * makes the area partial. `pattern` is tested against the file's namespace imports and class names.
 */
export const UNSUPPORTED_LIBRARIES: ReadonlyArray<{
  label: string;
  kind: "sql" | "process";
  pattern: RegExp;
}> = [
  { label: "WordPress wpdb", kind: "sql", pattern: /\$wpdb\b|\bwpdb\b/ },
  {
    label: "Doctrine QueryBuilder",
    kind: "sql",
    pattern: /Doctrine\\(?:ORM|DBAL)\\(?:Query\\)?QueryBuilder|->createQueryBuilder\(/,
  },
  {
    label: "RedBeanPHP",
    kind: "sql",
    pattern: /\bRedBeanPHP\\|\bR::(?:exec|getAll|getRow|getCol|getCell)\(/,
  },
  { label: "Laminas/Zend Db", kind: "sql", pattern: /\b(?:Laminas|Zend)\\Db\\/ },
  { label: "Yii DAO", kind: "sql", pattern: /->createCommand\(/ },
  { label: "CakePHP database", kind: "sql", pattern: /\bCake\\Database\\/ },
  { label: "Medoo", kind: "sql", pattern: /\bMedoo\\Medoo\b/ },
  { label: "Amp process", kind: "process", pattern: /\bAmp\\Process\\/ },
  { label: "Spatie shell", kind: "process", pattern: /\bSpatie\\(?:Async|Ssh)\\/ },
];
