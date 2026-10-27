// corpus: expect=low
import java.util.Set;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
class SortController {
  private static final Set<String> SORTABLE = Set.of("name", "created_at", "id");
  private final JdbcTemplate jdbcTemplate;

  SortController(JdbcTemplate jdbcTemplate) {
    this.jdbcTemplate = jdbcTemplate;
  }

  @GetMapping("/people")
  Object people(@RequestParam String sort) {
    if (!SORTABLE.contains(sort)) {
      throw new IllegalArgumentException("bad sort column");
    }
    return jdbcTemplate.queryForList("SELECT * FROM people ORDER BY " + sort);
  }
}
