// corpus: expect=PG-SQL-005
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.web.bind.annotation.*
// form: listOf(1).forEach { _ -> STMT }
@RestController class C(private val jdbc: JdbcTemplate) {
  @GetMapping("/a") fun a(@RequestParam q: String) {
    listOf(1).forEach { _ -> jdbc.execute("DELETE FROM t WHERE n = '$q'") }
  }
}
