// corpus: expect=PG-SQL-005
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.web.bind.annotation.*
@RestController class C(private val jdbc: JdbcTemplate) {
  private var current = "id"
  private val orderCol: String get() = current
  @PostMapping("/s") fun s(@RequestParam c: String) { current = c }
  @GetMapping("/r") fun r(): Any = jdbc.queryForList("SELECT * FROM t ORDER BY " + orderCol)
}
