// corpus: expect=PG-SQL-005
import java.util.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.*;
@RestController class C { JdbcTemplate jdbc;
  boolean isValid(String s) { return s != null; }
  @GetMapping("/r") Object run(@RequestParam String sort) { if (!isValid(sort)) return null; return jdbc.queryForList("SELECT * FROM t ORDER BY " + sort); }
}
