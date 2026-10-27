/**
 * Names the Python SQL injection (PG-SQL-006) and command execution (PG-CMD-004) rules recognize:
 * request input, DB-API and ORM sinks, process APIs, and the libraries the rules do not follow.
 */

// ------------------------------------------------------------------ request input

/** Attributes of a request object whose value is chosen by the client (Flask, Django, DRF, Starlette, aiohttp). */
export const REQUEST_ATTRS = new Set([
  "args",
  "form",
  "values",
  "json",
  "data",
  "cookies",
  "headers",
  "files",
  "view_args",
  "query_string",
  "get_json",
  "get_data",
  "stream",
  "GET",
  "POST",
  "COOKIES",
  "META",
  "body",
  "FILES",
  "query_params",
  "path_params",
  "path",
  "full_path",
  "url",
  "host",
  "query",
  "match_info",
  "params",
  "rel_url",
  "environ",
]);

/** A parameter with one of these annotations is the request object, not a value from it. */
export const REQUEST_TYPE = /^(?:Request|HttpRequest|WSGIRequest|ASGIRequest|HTTPConnection)$/;
/** A parameter with one of these annotations is something the framework supplies, not client data. */
export const FRAMEWORK_TYPE =
  /^(?:Session|AsyncSession|Response|HttpResponse|BackgroundTasks|WebSocket|Depends|Security|User|Connection|Engine|Cursor|Settings|Logger)$/;
/** Annotations whose values are numbers, booleans, dates or UUIDs: validated by the framework. */
export const NON_TEXT_TYPE =
  /^(?:int|float|bool|complex|Decimal|UUID|UUID4|date|datetime|time|timedelta|PositiveInt|NegativeInt|conint|confloat|StrictInt|StrictFloat|StrictBool)$/;

/** Decorator names that make a function a request handler (`@app.route`, `@router.get`, `@api_view`). */
export const HANDLER_DECORATORS = new Set([
  "route",
  "get",
  "post",
  "put",
  "delete",
  "patch",
  "head",
  "options",
  "trace",
  "api_route",
  "websocket",
  "api_view",
  "action",
  "endpoint",
  "view_config",
  "require_GET",
  "require_POST",
  "require_http_methods",
  "csrf_exempt",
  "login_required",
]);
/** Methods of a class-based view (Django, DRF): handlers when the second parameter is the request. */
export const VIEW_METHODS = new Set([
  "get",
  "post",
  "put",
  "patch",
  "delete",
  "head",
  "options",
  "list",
  "create",
  "retrieve",
  "update",
  "partial_update",
  "destroy",
]);

// ------------------------------------------------------------------ SQL

/** Top-level modules of the database drivers and ORMs the rule knows. A file importing one is a SQL file. */
export const SQL_MODULES = new Set([
  "sqlite3",
  "psycopg2",
  "psycopg",
  "pymysql",
  "MySQLdb",
  "mysql",
  "mariadb",
  "cx_Oracle",
  "oracledb",
  "pyodbc",
  "pymssql",
  "asyncpg",
  "aiopg",
  "aiomysql",
  "aiosqlite",
  "asyncmy",
  "pg8000",
  "duckdb",
  "databases",
  "sqlalchemy",
  "sqlmodel",
  "django",
  "peewee",
  "records",
  "pandas",
  "snowflake",
  "clickhouse_driver",
  "ibm_db",
]);

/** Methods that take SQL text as their first argument. */
export const DBAPI_SINKS = new Set([
  "execute",
  "executemany",
  "executescript",
  "exec_driver_sql",
  "execute_sql",
  "execute_query",
  "fetch",
  "fetchrow",
  "fetchval",
  "fetch_all",
  "fetch_one",
  "fetch_val",
]);
/** Of those, the ones whose name alone is too common: they need a SQL library in the file. */
export const GENERIC_DBAPI = new Set([
  "fetch",
  "fetchrow",
  "fetchval",
  "fetch_all",
  "fetch_one",
  "fetch_val",
]);
/** `module.function(cursor, sql, ...)`: SQL is the second argument. */
export const BATCH_FUNCTIONS = new Set(["execute_values", "execute_batch"]);
/** `pandas.read_sql*(sql, con)`. */
export const PANDAS_SINKS = new Set(["read_sql", "read_sql_query"]);

/** Text that reads like SQL. */
export const PY_SQL_TEXT =
  /\b(?:select|insert\s+into|replace\s+into|update|delete\s+from|from|where|values|union|order\s+by|group\s+by|join|having|limit|pragma|create\s+table|drop\s+table|alter\s+table|truncate)\b/i;
/** A receiver that is a cursor, connection, session or engine by its usual name. */
export const SQL_RECEIVER_NAME =
  /cursor|^cur$|conn|^con$|session|engine|database|^db|_db$|sqlite|psql|mysql|^c$|^pool|^dbh$|^sql/i;
/** Calls whose result is a connection, cursor, session or engine. */
export const DB_PRODUCERS = new Set([
  "cursor",
  "connect",
  "begin",
  "raw_connection",
  "get_connection",
  "session",
  "Session",
  "sessionmaker",
  "scoped_session",
  "create_engine",
  "create_async_engine",
  "get_db",
  "get_session",
  "async_session",
  "AsyncSession",
]);

/** Libraries with their own raw-SQL API that the rule does not follow. */
export const UNSUPPORTED_SQL_LIBRARIES: ReadonlyArray<{ module: string; label: string }> = [
  { module: "peewee", label: "peewee" },
  { module: "pony", label: "Pony ORM" },
  { module: "tortoise", label: "Tortoise ORM" },
  { module: "records", label: "Records" },
  { module: "sqlobject", label: "SQLObject" },
  { module: "storm", label: "Storm" },
  { module: "ormar", label: "ormar" },
  { module: "piccolo", label: "Piccolo" },
  { module: "aiosql", label: "aiosql" },
];

// ------------------------------------------------------------------ processes

/** Functions that run a string as a shell command. */
export const SHELL_STRING_FUNCTIONS = new Set([
  "os.system",
  "os.popen",
  "os.popen2",
  "os.popen3",
  "os.popen4",
  "commands.getoutput",
  "commands.getstatusoutput",
  "subprocess.getoutput",
  "subprocess.getstatusoutput",
  "asyncio.create_subprocess_shell",
  "popen2.popen2",
  "popen2.popen3",
  "popen2.popen4",
]);
/** Functions that start a process from a list (or from a string when `shell=True`). */
export const SUBPROCESS_FUNCTIONS = new Set([
  "subprocess.run",
  "subprocess.call",
  "subprocess.check_call",
  "subprocess.check_output",
  "subprocess.Popen",
  "pty.spawn",
]);
/** `asyncio.create_subprocess_exec(program, *args)`. */
export const EXEC_FUNCTIONS = new Set(["asyncio.create_subprocess_exec"]);
/** `os.execv(path, args)`, `os.spawnl(mode, path, ...)`. */
export const OS_EXEC = /^os\.(exec(?:l|le|lp|lpe|v|ve|vp|vpe)|spawn(?:l|le|lp|lpe|v|ve|vp|vpe))$/;

/** Libraries that run processes with their own API; the rule does not follow them. */
export const UNSUPPORTED_PROCESS_LIBRARIES: ReadonlyArray<{ module: string; label: string }> = [
  { module: "sh", label: "sh" },
  { module: "plumbum", label: "plumbum" },
  { module: "pexpect", label: "pexpect" },
  { module: "fabric", label: "Fabric" },
  { module: "invoke", label: "Invoke" },
  { module: "paramiko", label: "Paramiko" },
  { module: "asyncssh", label: "asyncssh" },
  { module: "delegator", label: "delegator.py" },
  { module: "envoy", label: "envoy" },
  { module: "sarge", label: "sarge" },
  { module: "pyinfra", label: "pyinfra" },
];

/** Modules whose names a star import would hide from the rules. */
export const STAR_IMPORT_MODULES = new Set([
  "os",
  "subprocess",
  "commands",
  "asyncio",
  "pty",
  "sqlite3",
  "psycopg2",
  "pymysql",
]);

// ------------------------------------------------------------------ values

/** Calls that give a number, boolean or date: not SQL text, but kept and demoted. */
export const COERCIONS = new Set([
  "int",
  "float",
  "bool",
  "complex",
  "len",
  "abs",
  "round",
  "ord",
  "hash",
  "id",
  "min",
  "max",
  "sum",
  "pow",
  "divmod",
  "Decimal",
  "UUID",
  "uuid4",
  "uuid1",
  "randint",
  "random",
  "time",
  "monotonic",
]);
/** Methods of a string (or mapping) that return the value it holds, changed or cut. */
export const STRING_PASS = new Set([
  "strip",
  "lstrip",
  "rstrip",
  "lower",
  "upper",
  "title",
  "capitalize",
  "casefold",
  "swapcase",
  "encode",
  "decode",
  "ljust",
  "rjust",
  "center",
  "zfill",
  "removeprefix",
  "removesuffix",
  "translate",
  "expandtabs",
  "copy",
  "to_dict",
  "get_json",
  "get_data",
  "read",
  "items",
  "values",
  "keys",
]);
/** Methods that split a string into pieces. */
export const SPLITTERS = new Set(["split", "rsplit", "splitlines", "partition", "rpartition"]);
/** Lookups: `d.get(key, default)`. */
export const LOOKUPS = new Set(["get", "getlist", "pop", "setdefault", "getfirst", "get_all"]);
/** Calls on a list that put values into it. */
export const ELEMENT_WRITERS = new Set([
  "append",
  "extend",
  "insert",
  "add",
  "update",
  "appendleft",
  "extendleft",
]);
/** Wrappers that keep the value of their argument (`SQL("...")`, `str(x)`). */
export const WRAPPERS = new Set([
  "str",
  "repr",
  "ascii",
  "bytes",
  "bytearray",
  "format",
  "SQL",
  "Composed",
  "text_type",
  "unicode",
]);
/** Functions that build a collection from their argument. */
export const COLLECTORS = new Set([
  "list",
  "tuple",
  "set",
  "frozenset",
  "sorted",
  "reversed",
  "iter",
  "dict",
  "enumerate",
  "zip",
  "map",
  "filter",
]);

/** Check functions named like validators: `is_valid_column(x)`. */
export const VALIDATOR_NAME = /allow|valid|whitelist|permit|safe|legit|known|support|sanitiz/i;
/** String methods that test what a string consists of. */
export const SHAPE_TESTS = new Set([
  "isdigit",
  "isnumeric",
  "isdecimal",
  "isalnum",
  "isalpha",
  "isidentifier",
]);
/** Annotations in `isinstance(x, T)` that mean x is a number. */
export const NUMERIC_CLASSES = new Set(["int", "float", "bool", "Decimal", "UUID"]);
/** Calls that end the function or the program. */
export const EXITING_CALLS = new Set(["abort", "exit", "quit", "_exit", "fail", "bail"]);

/** Top-level modules of the web frameworks: a file importing one has request handlers. */
export const WEB_MODULES = new Set([
  "django",
  "flask",
  "fastapi",
  "starlette",
  "rest_framework",
  "aiohttp",
  "sanic",
  "pyramid",
  "bottle",
  "quart",
  "falcon",
]);
