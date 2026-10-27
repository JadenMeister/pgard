// corpus: expect=PG-SQL-005
import java.util.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.*;
enum SortCol { ID, NAME }
@RestController class C { JdbcTemplate jdbc;
  static class Holder { String name() { return v; } String v; }
  @GetMapping("/r") Object r(@RequestParam String s) { Holder SortCol = new Holder(); SortCol.v = s; return jdbc.queryForList("SELECT * FROM t ORDER BY " + SortCol.name()); }
}
