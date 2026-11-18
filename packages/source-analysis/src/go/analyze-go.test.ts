import { describe, expect, it } from "vitest";
import { analyzeGoSource } from "./analyze-go.js";
import { maskGoSource } from "./lexer.js";
import { TIME_FACTOR, bestTimeOf, itScaled } from "../../../../tests/support/timing.js";

const go = (imports: string[], body: string) =>
  `package main\n\nimport (\n${imports.map((name) => `\t"${name}"`).join("\n")}\n)\n\n${body}\n`;
const rulesIn = (source: string) =>
  analyzeGoSource(source, "main.go").findings.map((f) => f.ruleId);

describe("maskGoSource", () => {
  it("removes comments and masks strings while keeping line numbers", () => {
    const { code, literals } = maskGoSource('a := "x // y" // comment\nb := `multi\nline`\nc := 1');
    expect(code).not.toContain("comment");
    expect(code.split("\n")).toHaveLength(4);
    expect(literals).toEqual(["x // y", "multi\nline"]);
  });
});

describe("PG-SQL-003 database/sql", () => {
  it("flags request input formatted into Query", () => {
    const findings = analyzeGoSource(
      go(
        ["database/sql", "fmt", "net/http"],
        `func h(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	rows, _ := db.Query(fmt.Sprintf("SELECT * FROM users WHERE id = %s", id))
	_ = rows
}`,
      ),
      "main.go",
    ).findings;
    expect(findings).toEqual([
      expect.objectContaining({ ruleId: "PG-SQL-003", severity: "high", line: 11 }),
    ]);
  });

  it("flags concatenation in ExecContext and dynamic variables", () => {
    expect(
      rulesIn(
        go(
          ["database/sql"],
          `func f(ctx context.Context, name string) {
	q := "DELETE FROM t WHERE name = '" + name + "'"
	db.ExecContext(ctx, q)
}`,
        ),
      ),
    ).toEqual(["PG-SQL-003"]);
  });

  it.each([
    [
      `func f(r *http.Request) { db.Query("SELECT * FROM users WHERE id = $1", r.FormValue("id")) }`,
    ],
    [`func f(id string) { db.QueryRowContext(ctx, "SELECT name FROM t WHERE id = ?", id) }`],
    [`func f() { db.Exec("UPDATE t SET a = 1 WHERE b = " + "2") }`],
    [`func f() { msg := fmt.Sprintf("SELECT %s", x) /* comment: db.Query(msg) */ }`],
  ])("does not flag placeholders, literals or comments: %s", (body) => {
    expect(rulesIn(go(["database/sql", "fmt", "net/http"], body))).toEqual([]);
  });

  it("ignores files that do not use database/sql", () => {
    expect(rulesIn(go(["fmt"], `func f() { x.Query(fmt.Sprintf("%s", y)) }`))).toEqual([]);
  });
});

describe("PG-SQL-004 GORM", () => {
  it("flags Raw/Where built with Sprintf or concatenation", () => {
    expect(
      rulesIn(
        go(
          ["gorm.io/gorm", "fmt"],
          `func f(c *gin.Context) {
	name := c.Query("name")
	db.Raw(fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", name)).Scan(&u)
	db.Where("name = '" + name + "'").First(&u)
}`,
        ),
      ),
    ).toEqual(["PG-SQL-004", "PG-SQL-004"]);
  });

  it("does not flag GORM placeholders", () => {
    expect(
      rulesIn(
        go(
          ["gorm.io/gorm"],
          `func f(name string) {
	db.Where("name = ?", name).First(&u)
	db.Raw("SELECT * FROM users WHERE id = ?", id).Scan(&u)
}`,
        ),
      ),
    ).toEqual([]);
  });
});

describe("PG-CMD-002", () => {
  it("flags sh -c with request input as critical", () => {
    const findings = analyzeGoSource(
      go(
        ["os/exec", "net/http"],
        `func h(w http.ResponseWriter, r *http.Request) {
	exec.Command("sh", "-c", "ping " + r.FormValue("host")).Run()
}`,
      ),
      "main.go",
    ).findings;
    expect(findings).toEqual([
      expect.objectContaining({ ruleId: "PG-CMD-002", severity: "critical" }),
    ]);
  });

  it("does not flag direct program calls with separate arguments or constant scripts", () => {
    expect(
      rulesIn(
        go(
          ["os/exec"],
          `func f(ref string) {
	exec.Command("git", "log", ref).Run()
	exec.Command("sh", "-c", "echo ok").Run()
}`,
        ),
      ),
    ).toEqual([]);
  });
});

describe("PG-SSRF-001 / PG-PATH-001", () => {
  it("flags request input used as URL or file path", () => {
    expect(
      rulesIn(
        go(
          ["net/http", "os"],
          `func h(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("url")
	http.Get(target)
	name := r.FormValue("file")
	os.ReadFile("/data/" + name)
	http.ServeFile(w, r, r.URL.Query().Get("p"))
}`,
        ),
      ),
    ).toEqual(["PG-SSRF-001", "PG-PATH-001", "PG-PATH-001"]);
  });

  it("does not flag fixed URLs or basename-sanitized paths", () => {
    expect(
      rulesIn(
        go(
          ["net/http", "os", "path/filepath"],
          `func h(w http.ResponseWriter, r *http.Request) {
	http.Get("https://api.example.com/x")
	name := filepath.Base(r.FormValue("file"))
	os.ReadFile(name)
}`,
        ),
      ),
    ).toEqual([]);
  });
});

describe("crypto and cookies", () => {
  it("flags MD5 of passwords and hardcoded signing keys without echoing them", () => {
    const findings = analyzeGoSource(
      go(
        ["crypto/md5", "github.com/golang-jwt/jwt/v5"],
        `func f(password string) {
	sum := md5.Sum([]byte(password))
	s, _ := token.SignedString([]byte("super-signing-value"))
}`,
      ),
      "main.go",
    ).findings;
    expect(findings.map((f) => f.ruleId)).toEqual(["PG-CRYPTO-001", "PG-CRYPTO-002"]);
    expect(JSON.stringify(findings)).not.toContain("super-signing-value");
  });

  it("follows a package-level key into SignedString and hmac.New", () => {
    const sign = (decls: string, body = "return t.SignedString(key)") =>
      analyzeGoSource(
        go(["github.com/golang-jwt/jwt/v5"], `${decls}\nfunc f() (string, error) {\n\t${body}\n}`),
        "main.go",
      ).findings;
    const viaVar = sign('var key = []byte("hardcoded-signing-secret")');
    expect(viaVar.map((f) => f.ruleId)).toEqual(["PG-CRYPTO-002"]);
    // A package variable may be overwritten from another file: medium, not high.
    expect(viaVar[0]).toMatchObject({ severity: "high", confidence: "medium" });
    expect(JSON.stringify(viaVar)).not.toContain("hardcoded-signing-secret");
    const viaConst = sign(
      'const secret = "hardcoded-signing-secret"',
      "return t.SignedString([]byte(secret))",
    );
    expect(viaConst[0]).toMatchObject({ confidence: "high" });
    expect(sign('var (\n\tkey = []byte("blocked-secret")\n)')).toHaveLength(1);
    // Written elsewhere, declared without a value, shadowed by a parameter or a local: no finding.
    expect(sign('var key []byte\nfunc init() { key = []byte(os.Getenv("K")) }')).toEqual([]);
    expect(sign('var key = []byte("x")\nfunc g() { key = load() }')).toEqual([]);
    expect(sign('var key = []byte("x")\nfunc g(key []byte) {}')).toEqual([]);
    expect(sign('var key = []byte("x")', "key := load(); return t.SignedString(key)")).toEqual([]);
    expect(sign('var key = []byte("x")\nvar _ = copy(key, other)')).toEqual([]);
  });

  it("does not flag MD5 of non-password data or keys from the environment", () => {
    expect(
      rulesIn(
        go(
          ["crypto/md5", "os"],
          `func f(body []byte) {
	sum := md5.Sum(body)
	s, _ := token.SignedString([]byte(os.Getenv("JWT_KEY")))
}`,
        ),
      ),
    ).toEqual([]);
  });

  it("flags session cookies missing flags and accepts complete ones", () => {
    expect(
      rulesIn(
        go(
          ["net/http"],
          `func f(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: "session", Value: v})
	http.SetCookie(w, &http.Cookie{Name: "session", Value: v, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
}`,
        ),
      ),
    ).toEqual(["PG-COOKIE-001"]);
  });
});

describe("GORM with request input (#85)", () => {
  it("flags GORM Order/Where with request input", () => {
    expect(
      rulesIn(
        go(
          ["gorm.io/gorm"],
          `func f(c *gin.Context) {
	db.Order(c.Query("sort")).Find(&u)
	s := c.Query("filter")
	db.Where(s).Find(&u)
}`,
        ),
      ),
    ).toEqual(["PG-SQL-004", "PG-SQL-004"]);
  });

  it("does not flag literal GORM arguments", () => {
    expect(
      rulesIn(go(["gorm.io/gorm"], 'func f() { db.Order("created_at desc").Find(&u) }')),
    ).toEqual([]);
  });
});

describe("linear cost and caps (#87)", () => {
  itScaled(
    "analyzes a large Go file quickly",
    () => {
      const build = (count: number) => {
        const body = Array.from(
          { length: count },
          (_, index) =>
            `\tv${index} := r.FormValue("k${index}")\n\tdb.Query(fmt.Sprintf("SELECT %s", v${index}))`,
        ).join("\n");
        return go(
          ["database/sql", "fmt", "net/http"],
          `func h(w http.ResponseWriter, r *http.Request) {\n${body}\n}`,
        );
      };
      const source = build(6000);
      const quarter = build(1500);
      expect(source.length).toBeGreaterThan(300_000);
      let analysis = analyzeGoSource(source, "big.go");
      const large = bestTimeOf(3, () => {
        analysis = analyzeGoSource(source, "big.go");
      });
      const small = bestTimeOf(3, () => analyzeGoSource(quarter, "big.go"));
      expect(large).toBeLessThan(3000 * TIME_FACTOR);
      // Four times the input: linear is about 4x, quadratic about 16x.
      expect(large / Math.max(small, 1)).toBeLessThan(10);
      expect(analysis.findings.length).toBeLessThanOrEqual(25);
      expect(analysis.cappedRules).toEqual(["PG-SQL-003"]);
    },
    60_000,
  );
});

describe("precision (#88)", () => {
  it("tracks Go `var q = ...` assignments", () => {
    expect(
      rulesIn(
        go(
          ["database/sql"],
          `func f(name string) {
	var q = "SELECT * FROM t WHERE n = '" + name + "'"
	db.Query(q)
}`,
        ),
      ),
    ).toEqual(["PG-SQL-003"]);
  });
});

describe("injection precision and recall (#242)", () => {
  const sqlGo = (body: string, extra = "") =>
    go(["database/sql", "fmt", "strconv", "net/http"], `${extra}\n${body}`);
  const found = (source: string) => analyzeGoSource(source, "main.go").findings;
  const strong = (source: string) =>
    found(source)
      .filter((finding) => finding.confidence !== "low")
      .map((finding) => finding.ruleId);

  it("fully suppresses package constants and strconv.Itoa of the whole expression", () => {
    expect(
      rulesIn(
        sqlGo(
          `func f(db *sql.DB) { db.Query(fmt.Sprintf("SELECT * FROM %s LIMIT %d", table, limit)) }`,
          `const (\n\ttable = "t"\n\tlimit = 5\n)`,
        ),
      ),
    ).toEqual([]);
    expect(
      rulesIn(sqlGo(`func f(db *sql.DB, id int) { db.Query("SELECT " + strconv.Itoa(id)) }`)),
    ).toEqual([]);
  });

  it("demotes block-local constants and parsed numbers to low confidence", () => {
    for (const body of [
      `func f(db *sql.DB, r *http.Request) {
	n, _ := strconv.Atoi(r.FormValue("n"))
	db.Query(fmt.Sprintf("SELECT * FROM t LIMIT %d", n))
}`,
      `func f(db *sql.DB) {
	const table = "t"
	db.Query("SELECT * FROM " + table)
}`,
    ]) {
      expect(rulesIn(sqlGo(body))).toEqual(["PG-SQL-003"]);
      expect(strong(sqlGo(body))).toEqual([]);
    }
  });

  it("does not trust a constant that a parameter, var or := of the same name shadows", () => {
    const table = `const table = "users"`;
    for (const body of [
      `func f(db *sql.DB, table string) { db.Query("SELECT * FROM " + table) }`,
      `func f(db *sql.DB, r *http.Request) { var table = r.FormValue("t"); db.Query("SELECT * FROM " + table) }`,
      `func f(db *sql.DB, r *http.Request) { table := r.FormValue("t"); db.Query("SELECT * FROM " + table) }`,
      `func f(db *sql.DB, r *http.Request) { if table, ok := r.URL.Query()["t"]; ok { db.Query("SELECT * FROM " + table[0]) } }`,
      `func pick(r *http.Request) string { return r.FormValue("t") }
func f(db *sql.DB, r *http.Request) { var table = pick(r); db.Query("SELECT * FROM " + table) }`,
    ])
      expect(rulesIn(sqlGo(body, table))).toEqual(["PG-SQL-003"]);
    expect(
      rulesIn(sqlGo(`func f(db *sql.DB) { db.Query("SELECT * FROM " + table) }`, table)),
    ).toEqual([]);
  });

  it("scopes a block-local const to its innermost block", () => {
    const source = sqlGo(`func f(db *sql.DB, r *http.Request) {
	if r.Method == "GET" {
		const table = "a"
		db.Query("SELECT * FROM " + table)
	} else {
		db.Query("SELECT * FROM " + table)
	}
}`);
    const findings = found(source);
    expect(findings).toHaveLength(2);
    // a use outside the declaring block makes the name untrusted everywhere
    expect(strong(source)).toEqual(["PG-SQL-003", "PG-SQL-003"]);
  });

  it("treats strconv.Itoa as fixed only when it is the whole expression", () => {
    expect(
      rulesIn(
        sqlGo(`func f(db *sql.DB, id int, clause string) { db.Query(strconv.Itoa(id) + clause) }`),
      ),
    ).toEqual(["PG-SQL-003"]);
    expect(
      strong(
        sqlGo(`func f(db *sql.DB, id int, clause string) { db.Query(strconv.Itoa(id) + clause) }`),
      ),
    ).toEqual(["PG-SQL-003"]);
  });

  describe("shell with an argument slice (PG-CMD-002)", () => {
    const exec = (body: string) => go(["os/exec", "net/http"], body);

    it("resolves a literal slice and flags a dynamic element", () => {
      const dynamic = exec(
        `func f(script string) {\n\targs := []string{"-c", script}\n\texec.Command("sh", args...).Run()\n}`,
      );
      expect(strong(dynamic)).toEqual(["PG-CMD-002"]);
      const fixed = exec(
        `func f() {\n\targs := []string{"-c", "uptime"}\n\texec.Command("sh", args...).Run()\n}`,
      );
      // resolved through the declaration only: kept at low confidence
      expect(rulesIn(fixed)).toEqual(["PG-CMD-002"]);
      expect(strong(fixed)).toEqual([]);
    });

    it("only reads the declaration in the enclosing function", () => {
      const source = exec(`func a() {
	args := []string{"-c", "uptime"}
	exec.Command("sh", args...).Run()
}
func b(r *http.Request) {
	args := []string{"-c", "ping " + r.FormValue("h")}
	exec.Command("sh", args...).Run()
}`);
      const findings = found(source);
      expect(findings).toHaveLength(2);
      expect(findings.filter((finding) => finding.confidence !== "low")).toHaveLength(1);
      expect(findings.find((finding) => finding.confidence !== "low")?.line).toBeGreaterThan(5);
    });

    it("keeps a low-confidence finding when the slice is indexed, reassigned or a parameter", () => {
      for (const body of [
        `func f(r *http.Request) {\n\targs := []string{"-c", "true"}\n\targs[1] = r.FormValue("c")\n\texec.Command("sh", args...).Run()\n}`,
        `func f(r *http.Request) {\n\targs := []string{"-c", "true"}\n\targs = other(r)\n\texec.Command("sh", args...).Run()\n}`,
        `func f(args []string) {\n\texec.Command("sh", args...).Run()\n}`,
      ]) {
        const [finding] = found(exec(body));
        expect(finding).toMatchObject({ ruleId: "PG-CMD-002", confidence: "low" });
      }
    });

    it("reads items appended to the slice", () => {
      expect(
        strong(
          exec(
            `func f(r *http.Request) {\n\targs := []string{"-c"}\n\targs = append(args, r.FormValue("c"))\n\texec.Command("sh", args...).Run()\n}`,
          ),
        ),
      ).toEqual(["PG-CMD-002"]);
      expect(
        strong(
          exec(
            `func f() {\n\targs := []string{"-c"}\n\targs = append(args, "uptime")\n\texec.Command("sh", args...).Run()\n}`,
          ),
        ),
      ).toEqual([]);
    });

    it("does not trust a block-local const used in another function", () => {
      const source = exec(`func defaults() string {
	const hookCmd = "true"
	return hookCmd
}
func run() { exec.Command("sh", "-c", hookCmd).Run() }`);
      expect(strong(source)).toEqual(["PG-CMD-002"]);
      const same = exec(
        `func run() {\n\tconst hookCmd = "true"\n\texec.Command("sh", "-c", hookCmd).Run()\n}`,
      );
      expect(rulesIn(same)).toEqual(["PG-CMD-002"]);
      expect(strong(same)).toEqual([]);
    });

    it("does not flag a package constant script", () => {
      expect(
        rulesIn(
          exec(`const health = "uptime"\nfunc f() { exec.Command("sh", "-c", health).Run() }`),
        ),
      ).toEqual([]);
    });
  });
});

describe("empty key placeholders (#271)", () => {
  const sign = (decls: string, body = "return t.SignedString(jwtKey)") =>
    analyzeGoSource(
      go(["github.com/golang-jwt/jwt/v5"], `${decls}\nfunc f() (string, error) {\n\t${body}\n}`),
      "main.go",
    ).findings;

  it("reports an empty package var as before (high, medium confidence) when nothing assigns it", () => {
    const [empty] = sign('var jwtKey = []byte("")');
    expect(empty).toMatchObject({
      ruleId: "PG-CRYPTO-002",
      severity: "high",
      confidence: "medium",
      status: "suspected",
    });
    expect(sign('var (\n\tjwtKey = []byte("")\n)')[0]).toMatchObject({ severity: "high" });
  });

  it("reports an empty package var that this file assigns elsewhere only as low", () => {
    const [assigned] = sign('var jwtKey = []byte("")\nfunc init() { jwtKey = load() }');
    expect(assigned).toMatchObject({ severity: "low", confidence: "low", status: "suspected" });
    expect(assigned?.evidence).toContain("assigned elsewhere in this file");
    // A non-empty var assigned elsewhere is not a constant: still no finding.
    expect(sign('var jwtKey = []byte("x")\nfunc init() { jwtKey = load() }')).toEqual([]);
  });

  it("reports a package var assigned only literals elsewhere in the file as high, other sources low", () => {
    for (const literal of ['[]byte("")', '[]byte("supersecret123")']) {
      expect(sign(`var jwtKey = []byte("")\nfunc init() { jwtKey = ${literal} }`)[0]).toMatchObject(
        {
          severity: "high",
        },
      );
    }
    // The same with the assignment on its own lines in a function body.
    expect(
      sign('var jwtKey = []byte("")\nfunc init() {\n\tjwtKey = []byte("supersecret123")\n}')[0],
    ).toMatchObject({ severity: "high" });
    expect(
      sign('var jwtKey = []byte("")\nfunc init() {\n\tjwtKey = []byte(os.Getenv("K"))\n}')[0],
    ).toMatchObject({ severity: "low" });
    // An environment read is not provable: low (empty initializer) or nothing (non-empty).
    expect(
      sign('var jwtKey = []byte("")\nfunc init() { jwtKey = []byte(os.Getenv("K")) }')[0],
    ).toMatchObject({ severity: "low" });
    expect(
      sign('var jwtKey = []byte("x")\nfunc init() { jwtKey = []byte(os.Getenv("K")) }'),
    ).toEqual([]);
    // A literal and then an environment read: not all literal.
    expect(
      sign(
        'var jwtKey = []byte("")\nfunc init() { jwtKey = []byte("a") }\nfunc g() { jwtKey = []byte(os.Getenv("K")) }',
      )[0],
    ).toMatchObject({ severity: "low" });
  });

  it("keeps an empty literal or constant used as the key a high finding", () => {
    expect(sign("", 'return t.SignedString([]byte(""))')[0]).toMatchObject({
      severity: "high",
      confidence: "high",
    });
    expect(sign('const jwtKey = ""', "return t.SignedString([]byte(jwtKey))")[0]).toMatchObject({
      severity: "high",
      confidence: "high",
    });
    expect(sign('var jwtKey = []byte("not-empty-secret")')[0]).toMatchObject({
      severity: "high",
      confidence: "medium",
    });
  });
});

describe("PG-PATH-001 taint is scoped per function (#298)", () => {
  const imports = ["net/http", "os", "github.com/gin-gonic/gin"];
  const paths = (body: string) =>
    analyzeGoSource(go(imports, body), "main.go")
      .findings.filter((f) => f.ruleId === "PG-PATH-001")
      .map((f) => f.line);

  it("does not flag a safe handler that reuses a variable name of a vulnerable one", () => {
    const body = `func vulnerable(c *gin.Context) {
	name := c.Query("name")
	os.ReadFile(name)
}

func safe(c *gin.Context) {
	name := "report.txt"
	os.ReadFile(name)
}`;
    const lines = paths(body);
    const text = go(imports, body).split("\n");
    // Only the vulnerable handler, which comes first.
    expect(lines).toHaveLength(1);
    expect(lines[0]).toBeLessThan(text.findIndex((line) => line.startsWith("func safe")));
  });

  it("does not flag a closure that declares its own variable of that name", () => {
    expect(
      paths(`func a(c *gin.Context) {
	name := c.Query("name")
	_ = name
}
func b() {
	h := func() {
		name := "fixed.txt"
		os.ReadFile(name)
	}
	h()
}`),
    ).toEqual([]);
  });

  it("still flags a package variable that flows into a handler", () => {
    expect(
      paths(`var target string

func set(c *gin.Context) {
	target = c.Query("p")
}

func read(c *gin.Context) {
	os.ReadFile(target)
}`),
    ).toHaveLength(1);
  });

  it("still flags a variable captured by a closure", () => {
    expect(
      paths(`func h(c *gin.Context) {
	file := c.Query("f")
	func() {
		os.ReadFile(file)
	}()
}`),
    ).toHaveLength(1);
    // Assigned inside the closure, read after it in the outer function.
    expect(
      paths(`func h(c *gin.Context) {
	var file string
	func() {
		file = c.Query("f")
	}()
	os.ReadFile(file)
}`),
    ).toHaveLength(1);
  });

  it("still flags a tainted variable passed as a parameter", () => {
    expect(
      paths(`func h(c *gin.Context) {
	p := c.Query("p")
	serve(p)
}

func serve(target string) {
	os.ReadFile(target)
}`),
    ).toHaveLength(1);
    // A different argument position does not taint the parameter.
    expect(
      paths(`func h(c *gin.Context) {
	serve("fixed.txt", c.Query("p"))
}

func serve(target string, other string) {
	os.ReadFile(target)
}`),
    ).toEqual([]);
    // Method with a receiver and parameters sharing a type.
    expect(
      paths(`func (s *S) h(c *gin.Context) {
	s.serve("a", c.Query("p"))
}

func (s *S) serve(a, target string) {
	os.ReadFile(target)
}`),
    ).toHaveLength(1);
  });

  it("still flags a struct field that carries request input", () => {
    expect(
      paths(`type req struct{ Path string }

func h(c *gin.Context) {
	r := req{Path: c.Query("p")}
	os.ReadFile(r.Path)
}`),
    ).toHaveLength(1);
  });

  it("scopes SQL taint the same way", () => {
    const sql = analyzeGoSource(
      go(
        ["database/sql", "github.com/gin-gonic/gin"],
        `func a(c *gin.Context, db *sql.DB) {
	id := c.Query("id")
	db.Query("SELECT * FROM t WHERE id = " + id)
}
func b(db *sql.DB) {
	id := "7"
	db.Query("SELECT * FROM t WHERE id = " + id)
}`,
      ),
      "main.go",
    ).findings.filter((f) => f.ruleId === "PG-SQL-003");
    // `a` carries request input; `b` only builds a string (no request input reaches it).
    expect(sql.map((f) => f.severity)).toEqual(["high", "medium"]);
    expect(sql[0]?.evidence).toContain("request input");
    expect(sql[1]?.evidence).toContain("no input source identified");
  });
});

describe("many top-level constants stay linear (#375)", () => {
  const generated = (count: number) =>
    `package main\n\nimport "os"\n\n${Array.from({ length: count }, (_, index) => `const C${index} = "v${index}"`).join("\n")}\n\nfunc f() { os.Open("x") }\n`;

  itScaled(
    "analyzes 20000 constants without a quadratic scope scan",
    () => {
      const large = generated(20_000);
      const quarter = generated(5_000);
      const big = bestTimeOf(5, () => analyzeGoSource(large, "gen.go"));
      const small = bestTimeOf(5, () => analyzeGoSource(quarter, "gen.go"));
      // Four times the input: linear is about 4x, the old per-constant scan about 16x. The ratio
      // does not depend on the machine; the absolute ceiling is only a hang guard (it took 9 s).
      expect(big / Math.max(small, 1)).toBeLessThan(12);
      expect(big).toBeLessThan(5000 * TIME_FACTOR);
    },
    60_000,
  );

  it("keeps block-local constants trusted only inside their block", () => {
    const sql = (body: string) =>
      analyzeGoSource(go(["database/sql", "fmt"], body), "main.go").findings.map((f) => f.severity);
    expect(
      sql(`func f(db *sql.DB) {
	const t = "users"
	db.Query("SELECT * FROM " + t)
}`),
    ).toEqual(["medium"]);
    // The same name used outside the block may be a package variable of another file.
    expect(
      sql(`func f(db *sql.DB) {
	const t = "users"
	db.Query("SELECT * FROM " + t)
}
func g(db *sql.DB) {
	db.Query("SELECT * FROM " + t)
}`),
    ).toEqual(["medium", "medium"]);
  });
});

describe("Go taint across same-file functions (#298 review)", () => {
  const imports = ["net/http", "os", "database/sql", "github.com/gin-gonic/gin"];
  const rules = (body: string, rule: string) =>
    analyzeGoSource(go(imports, body), "main.go").findings.filter((f) => f.ruleId === rule);

  it("follows a helper that returns request input into a caller that reuses the name", () => {
    const body = `func getFilename(r *http.Request) string {
	filename := r.URL.Query().Get("file")
	return filename
}

func download(w http.ResponseWriter, r *http.Request) {
	filename := getFilename(r)
	http.ServeFile(w, r, "/data/"+filename)
}`;
    expect(rules(body, "PG-PATH-001")).toHaveLength(1);
    // A helper that returns a constant does not taint its caller.
    expect(rules(body.replace('r.URL.Query().Get("file")', '"report.txt"'), "PG-PATH-001")).toEqual(
      [],
    );
  });

  it("follows a named result and a returned call", () => {
    const sql = rules(
      `func readSort(r *http.Request) (sort string) {
	sort = r.URL.Query().Get("sort")
	return
}

func list(db *sql.DB, r *http.Request) {
	sort := readSort(r)
	db.Query("SELECT * FROM t ORDER BY " + sort)
}`,
      "PG-SQL-003",
    );
    expect(sql.map((f) => [f.severity, f.confidence])).toEqual([["high", "high"]]);
    expect(
      rules(
        `func inner(r *http.Request) string { return r.URL.Query().Get("f") }
func outer(r *http.Request) string { return inner(r) }
func h(w http.ResponseWriter, r *http.Request) {
	f := outer(r)
	os.ReadFile(f)
}`,
        "PG-PATH-001",
      ),
    ).toHaveLength(1);
  });

  it("settles a long call chain declared in reverse order", () => {
    const hops = 8;
    const chain = Array.from({ length: hops }, (_, i) =>
      i === hops - 1
        ? `func hop${i}(p string) { os.ReadFile(p) }`
        : `func hop${i}(p string) { hop${i + 1}(p) }`,
    ).reverse();
    const body = `${chain.join("\n")}\nfunc h(c *gin.Context) {\n\tv := c.Query("x")\n\thop0(v)\n}`;
    expect(rules(body, "PG-PATH-001")).toHaveLength(1);
    // The same chain with a constant at the entry stays quiet.
    expect(rules(body.replace('c.Query("x")', '"fixed"'), "PG-PATH-001")).toEqual([]);
  });

  it("falls back to name-only taint for a method value, a function literal and a package literal", () => {
    expect(
      rules(
        `type S struct{}
func (s *S) Read(name string) { os.ReadFile(name) }
func h(c *gin.Context, s *S) {
	name := c.Query("n")
	f := s.Read
	f(name)
}`,
        "PG-PATH-001",
      ),
    ).toHaveLength(1);
    expect(
      rules(
        `var read = func(name string) { os.ReadFile(name) }
func h(c *gin.Context) {
	name := c.Query("n")
	read(name)
}`,
        "PG-PATH-001",
      ),
    ).toHaveLength(1);
    expect(
      rules(
        `func h(c *gin.Context) {
	name := c.Query("n")
	read := func(name string) { os.ReadFile(name) }
	read(name)
}`,
        "PG-PATH-001",
      ),
    ).toHaveLength(1);
  });

  it("does bounded work for many same-named methods and calls", () => {
    const build = (count: number) =>
      `package main\nimport "os"\n${Array.from({ length: count }, (_, i) => `func (t T${i}) Get(a string) { os.ReadFile(a) }\n`).join("")}func h(r *http.Request) {\n${Array.from({ length: count }, (_, i) => `\tT${i}{}.Get(r.FormValue("k${i}"))\n`).join("")}}\n`;
    const small = bestTimeOf(2, () => analyzeGoSource(build(1500), "m.go"));
    const large = bestTimeOf(2, () => analyzeGoSource(build(6000), "m.go"));
    // Four times the methods and calls: linear is about 4x, every call against every method 16x.
    expect(large / Math.max(small, 1)).toBeLessThan(10);
    expect(large).toBeLessThan(10_000 * TIME_FACTOR);
  });
});

describe("Go taint through struct fields and receivers (#298 review)", () => {
  const imports = ["net/http", "os", "database/sql", "github.com/gin-gonic/gin"];
  const rules = (body: string, rule = "PG-PATH-001") =>
    analyzeGoSource(go(imports, body), "main.go").findings.filter((f) => f.ruleId === rule);

  it("follows a struct built from request input into a method that reads the field", () => {
    const body = `type Store struct{ file string }

func (s Store) read() { os.ReadFile(s.file) }

func h(r *http.Request) {
	s := Store{file: r.FormValue("file")}
	s.read()
}`;
    expect(rules(body)).toHaveLength(1);
    // Constant field: quiet.
    expect(rules(body.replace('r.FormValue("file")', '"a.txt"'))).toEqual([]);
    // A literal receiver and a pointer receiver.
    expect(
      rules(`type Store struct{ file string }
func (s *Store) read() { os.ReadFile(s.file) }
func h(r *http.Request) {
	(&Store{file: r.FormValue("file")}).read()
}`),
    ).toHaveLength(1);
    // A field set after construction.
    expect(
      rules(`type Store struct{ file string }
func (s *Store) read() { os.ReadFile(s.file) }
func h(r *http.Request) {
	s := &Store{}
	s.file = r.FormValue("file")
	s.read()
}`),
    ).toHaveLength(1);
  });

  it("does not taint another type's method of the same name when the receiver type is known", () => {
    const body = `type A struct{ file string }
type B struct{ file string }

func (a A) read() { os.ReadFile(a.file) }
func (b B) read() { os.ReadFile(b.file) }

func h(r *http.Request) {
	b := B{file: r.FormValue("file")}
	b.read()
}`;
    const found = rules(body);
    expect(found).toHaveLength(1);
    // Only B.read: the finding is on the line of `os.ReadFile(b.file)`.
    const text = go(imports, body).split("\n");
    expect(text[(found[0]?.line ?? 1) - 1]).toContain("b.file");
  });

  it("follows a receiver through a named return and an aliased method value", () => {
    expect(
      rules(`type Store struct{ file string }
func (s Store) path() (p string) { p = s.file; return }
func h(r *http.Request) {
	s := Store{file: r.FormValue("file")}
	os.ReadFile(s.path())
}`),
    ).toHaveLength(1);
    expect(
      rules(`type Store struct{ file string }
func (s Store) read() { os.ReadFile(s.file) }
func h(r *http.Request) {
	s := Store{file: r.FormValue("file")}
	f := s.read
	f()
}`),
    ).toHaveLength(1);
  });

  it("keeps a package variable tainted when a function also declares an inner variable of that name", () => {
    const body = `var file string

func set(c *gin.Context) {
	file = c.Query("f")
	{
		file := "unrelated.txt"
		_ = file
	}
}

func read(c *gin.Context) {
	os.ReadFile(file)
}`;
    expect(rules(body)).toHaveLength(1);
  });
});
