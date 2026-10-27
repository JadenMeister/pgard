// corpus: expect=PG-SQL-005
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.web.bind.annotation.*
@RestController class C(private val jdbc: JdbcTemplate) {
  @GetMapping("/r") fun r(@RequestParam cols: List<String>): Any {
    val sb = StringBuilder("SELECT id")
    cols.forEach(sb::append)
    sb.append(" FROM t")
    return jdbc.queryForList(sb.toString())
  } }
