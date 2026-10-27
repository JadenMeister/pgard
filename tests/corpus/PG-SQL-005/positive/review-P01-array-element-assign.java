// corpus: expect=PG-SQL-005
import java.util.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.*;
@RestController class C { JdbcTemplate jdbc;
  @GetMapping("/a") Object a(@RequestParam String sort) {
    String[] cols = {"id", "name"};
    cols[1] = sort;
    return jdbc.queryForList("SELECT " + String.join(",", cols) + " FROM t");
  } }
