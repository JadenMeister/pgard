// corpus: expect=low
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
class PagingController {
  private JdbcTemplate jdbc;

  @GetMapping("/feed")
  Object feed(@RequestParam int page, @RequestParam Long size) {
    return jdbc.queryForList("SELECT * FROM feed LIMIT " + size + " OFFSET " + (page * 20));
  }
}
