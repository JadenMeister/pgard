// corpus: expect=PG-SQL-005
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.web.bind.annotation.*
// form: do { STMT } while (false)
@RestController class C(private val jdbc: JdbcTemplate) {
  @GetMapping("/a") fun a(@RequestParam q: String) {
    do { jdbc.execute("DELETE FROM t WHERE n = '$q'") } while (false)
  }
}
