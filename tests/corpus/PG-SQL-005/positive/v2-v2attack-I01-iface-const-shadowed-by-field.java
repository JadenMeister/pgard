// corpus: expect=PG-SQL-005
import java.util.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.*;
interface Cols { String COL = "id"; }
@RestController class C implements Cols { JdbcTemplate jdbc; String COL;
  @PostMapping("/s") void s(@RequestParam String c) { COL = c; }
  @GetMapping("/r") Object r() { return jdbc.queryForList("SELECT * FROM t ORDER BY " + COL); }
}
