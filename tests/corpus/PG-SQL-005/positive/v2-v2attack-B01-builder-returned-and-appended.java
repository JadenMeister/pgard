// corpus: expect=PG-SQL-005
import java.util.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.*;
@RestController class C { JdbcTemplate jdbc;
  StringBuilder same(StringBuilder b) { return b; }
  @GetMapping("/r") Object r(@RequestParam String s) { StringBuilder sb = new StringBuilder("SELECT * FROM t"); same(sb).append(" ORDER BY ").append(s); return jdbc.queryForList(sb.toString()); }
}
