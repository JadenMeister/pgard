// corpus: expect=PG-SQL-005
import java.util.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.*;
@RestController class C { JdbcTemplate jdbc;
  @GetMapping("/r") Object r(@RequestParam String s, @RequestParam boolean x) { StringBuilder sb = new StringBuilder("SELECT * FROM t"); StringBuilder other = new StringBuilder(); StringBuilder t = x ? sb : other; t.append(" ORDER BY ").append(s); return jdbc.queryForList(sb.toString()); }
}
