// corpus: expect=PG-SQL-005
import java.util.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.*;
interface Cols { String[] COLS = {"id", "name"}; }
@RestController class C implements Cols { JdbcTemplate jdbc;
  @PostMapping("/s") void s(@RequestParam String c) { String[] a = COLS; a[0] = c; }
  @GetMapping("/r") Object r() { return jdbc.queryForList("SELECT " + String.join(",", COLS) + " FROM t"); }
}
