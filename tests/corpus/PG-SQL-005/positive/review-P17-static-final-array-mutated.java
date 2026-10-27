// corpus: expect=PG-SQL-005
import java.util.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.*;
@RestController class C { JdbcTemplate jdbc;
  static final String[] COLS = {"id", "name"};
  @GetMapping("/s") void set(@RequestParam String c) { COLS[0] = c; }
  @GetMapping("/r") Object run() { return jdbc.queryForList("SELECT * FROM t ORDER BY " + COLS[0]); }
}
