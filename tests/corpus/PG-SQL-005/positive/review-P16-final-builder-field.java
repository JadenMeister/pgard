// corpus: expect=PG-SQL-005
import java.util.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.*;
@RestController class C { JdbcTemplate jdbc;
  private final StringBuilder base = new StringBuilder("SELECT * FROM t");
  @GetMapping("/r") Object run() { return jdbc.queryForList(base.toString()); }
  @GetMapping("/f") void filter(@RequestParam String where) { base.append(" WHERE ").append(where); }
}
