// corpus: expect=PG-SQL-005
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.web.bind.annotation.*
// form: when { q.isEmpty() -> Unit; else -> STMT }
@RestController class C(private val jdbc: JdbcTemplate) {
  @GetMapping("/a") fun a(@RequestParam q: String) {
    when { q.isEmpty() -> Unit; else -> jdbc.execute("DELETE FROM t WHERE n = '$q'") }
  }
}
