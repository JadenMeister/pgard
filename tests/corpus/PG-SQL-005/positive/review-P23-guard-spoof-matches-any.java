// corpus: expect=PG-SQL-005
import java.util.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.*;
@RestController class C { JdbcTemplate jdbc;
  @GetMapping("/r") Object run(@RequestParam String sort) { if (sort.matches(".*")) { return jdbc.queryForList("SELECT * FROM t ORDER BY " + sort); } return null; }
}
