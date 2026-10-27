// corpus: expect=PG-SQL-005
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.web.bind.annotation.*
// form: repeat(2) { STMT }
@RestController class C(private val jdbc: JdbcTemplate) {
  @GetMapping("/a") fun a(@RequestParam q: String) {
    repeat(2) { jdbc.execute("DELETE FROM t WHERE n = '$q'") }
  }
}
