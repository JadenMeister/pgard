// corpus: expect=PG-SQL-005
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.web.bind.annotation.*
@RestController class C(private val jdbc: JdbcTemplate) {
  @GetMapping("/a") fun a(@RequestParam cols: List<String>): Any {
    var sel = "id"
    for (c in cols) { sel += ", $c" }
    return jdbc.queryForList("SELECT $sel FROM t")
  } }
