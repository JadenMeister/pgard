// corpus: expect=PG-SQL-005
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.web.bind.annotation.*
@RestController class C(private val jdbc: JdbcTemplate) {
  @GetMapping("/r") fun r(@RequestParam s: String): Any {
    val sb = StringBuilder("SELECT * FROM t")
    sb.apply { append(" ORDER BY ") }.also { b -> b.append(s) }
    return jdbc.queryForList(sb.toString())
  } }
