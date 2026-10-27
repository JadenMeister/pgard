// corpus: expect=PG-SQL-005
import java.util.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.*;
@RestController class C { JdbcTemplate jdbc; private final StringBuilder base;
  C() { base = new StringBuilder("SELECT * FROM t"); }
  @GetMapping("/f") void f(@RequestParam String w) { base.append(" WHERE ").append(w); }
  @GetMapping("/r") Object r() { return jdbc.queryForList(base.toString()); }
}
