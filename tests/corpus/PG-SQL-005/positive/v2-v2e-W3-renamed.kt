// corpus: expect=PG-SQL-005
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.web.bind.annotation.*
@RestController class C(private val jdbc: JdbcTemplate) {
  @GetMapping("/r") fun r(@RequestParam s: String): Any {
    var cond = ""
    if (s.isNotEmpty()) cond = " WHERE n = '$s'"
    return jdbc.queryForList("SELECT * FROM t" + cond)
  } }
