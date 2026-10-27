// corpus: expect=PG-SQL-005
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.web.bind.annotation.*
// form: if (q.isNotEmpty()) STMT else Unit
@RestController class C(private val jdbc: JdbcTemplate) {
  @GetMapping("/a") fun a(@RequestParam q: String) {
    if (q.isNotEmpty()) jdbc.execute("DELETE FROM t WHERE n = '$q'") else Unit
  }
}
