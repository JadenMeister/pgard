// corpus: expect=PG-SQL-005
import java.util.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.*;
@RestController class C { JdbcTemplate jdbc;
  String clean(String s) { return s.replace("--", ""); }
  @GetMapping("/r") Object run(@RequestParam String q) { return jdbc.queryForList(buildQuery(clean(q))); }
  String buildQuery(String v) { return "SELECT * FROM t WHERE n = '" + v + "'"; }
}
