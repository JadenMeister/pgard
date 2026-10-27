// corpus: expect=PG-SQL-005
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.web.bind.annotation.*
@RestController class C(private val jdbc: JdbcTemplate) {
  private val col by lazy { System.getenv("COL") ?: "id" }
  @GetMapping("/r") fun r(): Any = jdbc.queryForList("SELECT * FROM t ORDER BY $col")
}
