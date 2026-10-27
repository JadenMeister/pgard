// corpus: expect=PG-SQL-005
import java.util.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.*;
interface Cols { String COL = "id"; }
class Base implements Cols { static String COL = "x"; }
@RestController class C extends Base { JdbcTemplate jdbc;
  @PostMapping("/s") void s(@RequestParam String c) { COL = c; }
  @GetMapping("/r") Object r() { return jdbc.queryForList("SELECT * FROM t ORDER BY " + COL); }
}
