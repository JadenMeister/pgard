// corpus: expect=PG-SQL-005
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.web.bind.annotation.*
data class F(val title: String)
@RestController class C(private val jdbc: JdbcTemplate) {
  @PostMapping("/a") fun a(@RequestBody f: F) = jdbc.queryForList("SELECT * FROM t WHERE title = '${f.title}'")
}
