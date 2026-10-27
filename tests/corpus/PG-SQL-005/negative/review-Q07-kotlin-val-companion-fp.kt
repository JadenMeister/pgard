// corpus: expect=none
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.web.bind.annotation.*
@RestController class C(private val jdbc: JdbcTemplate) {
  companion object { private val BASE = "SELECT * FROM t" }
  @GetMapping("/a") fun a(@RequestParam desc: Boolean): Any = jdbc.queryForList(BASE + " ORDER BY id" + (if (desc) " DESC" else ""))
}
