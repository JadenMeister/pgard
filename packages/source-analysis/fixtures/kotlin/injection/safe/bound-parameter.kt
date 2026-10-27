import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController

@RestController
class UserController(private val jdbcTemplate: JdbcTemplate) {
    @GetMapping("/users")
    fun byName(@RequestParam name: String) =
        jdbcTemplate.queryForList("SELECT * FROM users WHERE name = ?", name)
}
