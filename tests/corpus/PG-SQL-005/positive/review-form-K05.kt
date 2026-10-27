// corpus: expect=PG-SQL-005
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.web.bind.annotation.*
// form: q.takeIf { it.isNotBlank() }?.let { STMT }
@RestController class C(private val jdbc: JdbcTemplate) {
  @GetMapping("/a") fun a(@RequestParam q: String) {
    q.takeIf { it.isNotBlank() }?.let { jdbc.execute("DELETE FROM t WHERE n = '$q'") }
  }
}
