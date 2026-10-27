// corpus: expect=low
import java.util.Map;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
class ColumnController {
  private static final Map<String, String> COLUMNS = Map.of("new", "created_at DESC", "name", "name ASC");
  private JdbcTemplate jdbc;

  @GetMapping("/posts")
  Object posts(@RequestParam String sort) {
    String order = COLUMNS.getOrDefault(sort, "created_at DESC");
    return jdbc.queryForList("SELECT * FROM posts ORDER BY " + order);
  }
}
