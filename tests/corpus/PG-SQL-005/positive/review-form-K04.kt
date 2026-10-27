// corpus: expect=PG-SQL-005
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.web.bind.annotation.*
// form: val r = try { STMT } finally { }
@RestController class C(private val jdbc: JdbcTemplate) {
  @GetMapping("/a") fun a(@RequestParam q: String) {
    val r = try { jdbc.execute("DELETE FROM t WHERE n = '$q'") } finally { }
  }
}
