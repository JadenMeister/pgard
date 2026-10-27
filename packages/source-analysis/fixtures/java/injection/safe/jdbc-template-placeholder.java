import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
class UserController {
  private JdbcTemplate jdbcTemplate;

  @GetMapping("/users")
  Object byEmail(@RequestParam String email) {
    return jdbcTemplate.queryForList("SELECT * FROM users WHERE email = ?", email);
  }
}
