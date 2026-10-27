// corpus: expect=PG-SQL-005
package com.example.users;

import java.util.List;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class UserController {
  private final JdbcTemplate jdbcTemplate;

  public UserController(JdbcTemplate jdbcTemplate) {
    this.jdbcTemplate = jdbcTemplate;
  }

  @GetMapping("/users")
  public List<User> search(@RequestParam("name") String name) {
    String sql = "SELECT id, name, email FROM users WHERE name = '" + name + "'";
    return jdbcTemplate.query(sql, (rs, i) -> new User(rs.getLong(1), rs.getString(2), rs.getString(3)));
  }
}
