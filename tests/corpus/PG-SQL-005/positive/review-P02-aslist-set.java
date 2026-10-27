// corpus: expect=PG-SQL-005
import java.util.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.*;
@RestController class C { JdbcTemplate jdbc;
  @GetMapping("/a") Object a(@RequestParam String sort) {
    List<String> cols = Arrays.asList("id", "name");
    cols.set(0, sort);
    return jdbc.queryForList("SELECT * FROM t ORDER BY " + cols.get(0));
  } }
