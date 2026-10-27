// corpus: expect=PG-SQL-005
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.web.bind.annotation.*
@RestController class C(private val jdbc: JdbcTemplate) {
  @GetMapping("/a") fun a(@RequestParam sort: String): Any {
    val sb = StringBuilder("SELECT * FROM t ORDER BY ")
    sb.let { b -> b.append(sort) }
    return jdbc.queryForList(sb.toString())
  } }
