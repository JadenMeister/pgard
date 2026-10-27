// corpus: expect=PG-SQL-005
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.web.bind.annotation.*
// form: val x = object : Runnable { override fun run() { STMT } }
@RestController class C(private val jdbc: JdbcTemplate) {
  @GetMapping("/a") fun a(@RequestParam q: String) {
    val x = object : Runnable { override fun run() { jdbc.execute("DELETE FROM t WHERE n = '$q'") } }
  }
}
