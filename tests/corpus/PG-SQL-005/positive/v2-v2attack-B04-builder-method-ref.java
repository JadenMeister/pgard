// corpus: expect=PG-SQL-005
import java.util.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.*;
@RestController class C { JdbcTemplate jdbc;
  @GetMapping("/r") Object r(@RequestParam List<String> cols) { StringBuilder sb = new StringBuilder("SELECT id"); cols.forEach(sb::append); sb.append(" FROM t"); return jdbc.queryForList(sb.toString()); }
}
