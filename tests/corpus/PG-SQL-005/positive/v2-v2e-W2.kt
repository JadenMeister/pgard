// corpus: expect=PG-SQL-005
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.web.bind.annotation.*
@RestController class C(private val jdbc: JdbcTemplate) {
  @GetMapping("/r") fun r(@RequestParam s: String): Any {
    var where = ""
    if (s.isNotEmpty()) where = " WHERE n = '$s'"
    return jdbc.queryForList("SELECT * FROM t" + where)
  } }
