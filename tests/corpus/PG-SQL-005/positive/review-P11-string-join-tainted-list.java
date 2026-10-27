// corpus: expect=PG-SQL-005
import java.util.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.*;
@RestController class C { JdbcTemplate jdbc;
  @GetMapping("/a") Object a(@RequestParam String extra) {
    List<String> cols = new ArrayList<>(List.of("id", "name"));
    cols.add(extra);
    return jdbc.queryForList("SELECT " + String.join(",", cols) + " FROM t");
  } }
