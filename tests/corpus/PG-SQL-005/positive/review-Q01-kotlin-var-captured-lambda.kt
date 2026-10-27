// corpus: expect=PG-SQL-005
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.web.bind.annotation.*
@RestController class C(private val jdbc: JdbcTemplate) {
  @GetMapping("/a") fun a(@RequestParam sort: String): Any {
    var col = "id"
    val q = { jdbc.queryForList("SELECT * FROM t ORDER BY $col") }
    col = sort
    return q()
  } }
