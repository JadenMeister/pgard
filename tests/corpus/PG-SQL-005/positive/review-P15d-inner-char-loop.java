// corpus: expect=PG-SQL-005
import java.util.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.*;
@RestController class C { JdbcTemplate jdbc;
  @GetMapping("/a") Object a(@RequestParam List<String> cols) {
    String last = "id";
    for (String c : cols) {
      for (char ch : c.toCharArray()) { if (ch == 'x') continue; }
      last = c;
    }
    return jdbc.queryForList("SELECT * FROM t ORDER BY " + last);
  } }
