// corpus: expect=PG-SQL-005
import java.util.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.*;
@RestController class C { JdbcTemplate jdbc;
  private final String table;
  C(String table) { this.table = table; }
  @GetMapping("/r") Object run() { return jdbc.queryForList("SELECT * FROM " + table); }
}
