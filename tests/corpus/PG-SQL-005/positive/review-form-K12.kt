// corpus: expect=PG-SQL-005
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.web.bind.annotation.*
// form: outer@ while (true) { STMT; break@outer }
@RestController class C(private val jdbc: JdbcTemplate) {
  @GetMapping("/a") fun a(@RequestParam q: String) {
    outer@ while (true) { jdbc.execute("DELETE FROM t WHERE n = '$q'"); break@outer }
  }
}
