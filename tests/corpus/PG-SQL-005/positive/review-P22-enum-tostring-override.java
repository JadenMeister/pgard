// corpus: expect=PG-SQL-005
import java.util.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.*;
enum Col { NAME; String raw = ""; public String toString() { return raw; } }
@RestController class C { JdbcTemplate jdbc;
  @GetMapping("/r") Object run(@RequestParam String v) { Col c = Col.NAME; c.raw = v; return jdbc.queryForList("SELECT * FROM t ORDER BY " + c.toString()); }
}
