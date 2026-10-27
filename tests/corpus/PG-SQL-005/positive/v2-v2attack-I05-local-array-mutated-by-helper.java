// corpus: expect=PG-SQL-005
import java.util.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.*;
@RestController class C { JdbcTemplate jdbc;
  static void applySort(String[] cols, String s) { cols[0] = s; }
  @GetMapping("/r") Object r(@RequestParam String s) { String[] cols = {"id", "name"}; applySort(cols, s); return jdbc.queryForList("SELECT " + String.join(",", cols) + " FROM t"); }
}
