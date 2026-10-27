// corpus: expect=PG-SQL-005
import java.util.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.*;
interface Cols { String COL = "id"; }
@RestController class C implements Cols { JdbcTemplate jdbc;
  @GetMapping("/r") Object r(@RequestParam String c) { String COL = c; return jdbc.queryForList("SELECT * FROM t ORDER BY " + COL); }
}
