import { describe, expect, it } from "vitest";
import { analyzeGoSource } from "./analyze-go.js";
import { maskGoSource } from "./lexer.js";

const go = (imports: string[], body: string) =>
  `package main\n\nimport (\n${imports.map((name) => `\t"${name}"`).join("\n")}\n)\n\n${body}\n`;
const rulesIn = (source: string) =>
  analyzeGoSource(source, "main.go").findings.map((f) => f.ruleId);

/** Fastest of `runs` timings in ms: one run is noisy when other test files run in parallel. */
const bestTimeOf = (runs: number, fn: () => void) => {
  let best = Infinity;
  for (let run = 0; run < runs; run += 1) {
    const start = performance.now();
    fn();
    best = Math.min(best, performance.now() - start);
  }
  return best;
};

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
  it("analyzes a large Go file quickly", () => {
    const body = Array.from(
      { length: 6000 },
      (_, index) =>
        `\tv${index} := r.FormValue("k${index}")\n\tdb.Query(fmt.Sprintf("SELECT %s", v${index}))`,
    ).join("\n");
    const source = go(
      ["database/sql", "fmt", "net/http"],
      `func h(w http.ResponseWriter, r *http.Request) {\n${body}\n}`,
    );
    expect(source.length).toBeGreaterThan(300_000);
    let analysis = analyzeGoSource(source, "big.go");
    expect(
      bestTimeOf(3, () => {
        analysis = analyzeGoSource(source, "big.go");
      }),
    ).toBeLessThan(3000);
    expect(analysis.findings.length).toBeLessThanOrEqual(25);
    expect(analysis.cappedRules).toEqual(["PG-SQL-003"]);
  }, 60_000);
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
