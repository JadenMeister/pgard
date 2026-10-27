// corpus: expect=PG-SQL-005
import java.util.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.*;
@RestController class C { JdbcTemplate jdbc;
  @GetMapping("/a") Object a(@RequestParam String sort, boolean x) {
    StringBuilder sql = new StringBuilder("SELECT * FROM t");
    StringBuilder target = new StringBuilder();
    if (x) { target = sql; }
    target.append(" ORDER BY ").append(sort);
    return jdbc.queryForList(sql.toString());
  } }
