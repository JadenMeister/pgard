// corpus: expect=PG-SQL-005
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.web.bind.annotation.*
// form: synchronized(this) { STMT }
@RestController class C(private val jdbc: JdbcTemplate) {
  @GetMapping("/a") fun a(@RequestParam q: String) {
    synchronized(this) { jdbc.execute("DELETE FROM t WHERE n = '$q'") }
  }
}
