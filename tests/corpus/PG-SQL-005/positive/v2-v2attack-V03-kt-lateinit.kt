// corpus: expect=PG-SQL-005
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.web.bind.annotation.*
@RestController class C(private val jdbc: JdbcTemplate) {
  lateinit var col: String
  @PostMapping("/s") fun s(@RequestParam c: String) { col = c }
  @GetMapping("/r") fun r(): Any = jdbc.queryForList("SELECT * FROM t ORDER BY $col")
}
