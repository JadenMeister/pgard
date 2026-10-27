// corpus: expect=PG-SQL-005
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.*;
@RestController class C { JdbcTemplate jdbc; private String sql = "SELECT * FROM t";
  @PostMapping("/f") void f(@RequestParam String w) { sql = "SELECT * FROM t WHERE " + w; }
  @GetMapping("/r") Object r() { return jdbc.queryForList(sql); }
}
