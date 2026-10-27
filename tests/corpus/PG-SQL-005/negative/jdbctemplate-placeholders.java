// corpus: expect=none
import java.util.List;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
class CatalogController {
  private final JdbcTemplate jdbcTemplate;

  CatalogController(JdbcTemplate jdbcTemplate) {
    this.jdbcTemplate = jdbcTemplate;
  }

  @GetMapping("/catalog")
  List<String> names(@RequestParam String category, @RequestParam String brand) {
    return jdbcTemplate.queryForList(
        "SELECT name FROM catalog WHERE category = ? AND brand = ?", String.class, category, brand);
  }
}
