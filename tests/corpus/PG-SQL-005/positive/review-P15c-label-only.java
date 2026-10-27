// corpus: expect=PG-SQL-005
import java.util.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.*;
@RestController class C { JdbcTemplate jdbc;
  @GetMapping("/a") Object a(@RequestParam List<String> cols) {
    String last = "id";
    outer:
    for (String c : cols) {
      last = c;
    }
    return jdbc.queryForList("SELECT * FROM t ORDER BY " + last);
  } }
