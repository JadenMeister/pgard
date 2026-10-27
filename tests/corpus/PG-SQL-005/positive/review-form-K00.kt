// corpus: expect=PG-SQL-005
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.web.bind.annotation.*
// form: try { STMT } catch (e: Exception) { }
@RestController class C(private val jdbc: JdbcTemplate) {
  @GetMapping("/a") fun a(@RequestParam q: String) {
    try { jdbc.execute("DELETE FROM t WHERE n = '$q'") } catch (e: Exception) { }
  }
}
