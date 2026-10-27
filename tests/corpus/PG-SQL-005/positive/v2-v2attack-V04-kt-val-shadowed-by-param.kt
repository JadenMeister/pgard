// corpus: expect=PG-SQL-005
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.web.bind.annotation.*
@RestController class C(private val jdbc: JdbcTemplate) {
  private val col = "id"
  @GetMapping("/r") fun r(@RequestParam col: String): Any = jdbc.queryForList("SELECT * FROM t ORDER BY $col")
}
