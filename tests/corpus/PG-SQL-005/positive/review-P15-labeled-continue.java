// corpus: expect=PG-SQL-005
import java.util.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.*;
@RestController class C { JdbcTemplate jdbc;
  @GetMapping("/a") Object a(@RequestParam List<String> cols) {
    String last = "id";
    outer:
    for (String c : cols) {
      for (char ch : c.toCharArray()) { if (ch == 0x27) continue outer; }
      last = c;
    }
    return jdbc.queryForList("SELECT * FROM t ORDER BY " + last);
  } }
