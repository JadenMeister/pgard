// corpus: expect=PG-SQL-005
import java.util.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.*;
@RestController class C { JdbcTemplate jdbc;
  @GetMapping("/r") Object r(@RequestParam String s) { StringBuilder sb = new StringBuilder("SELECT * FROM t"); Runnable later = () -> sb.append(" WHERE n = '" + s + "'"); Object first = jdbc.queryForList(sb.toString()); later.run(); return first; }
}
