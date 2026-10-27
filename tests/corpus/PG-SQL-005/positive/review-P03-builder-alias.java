// corpus: expect=PG-SQL-005
import java.util.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.*;
@RestController class C { JdbcTemplate jdbc;
  @GetMapping("/a") Object a(@RequestParam String sort) {
    StringBuilder sql = new StringBuilder("SELECT * FROM t");
    StringBuilder tail = sql;
    tail.append(" ORDER BY ").append(sort);
    return jdbc.queryForList(sql.toString());
  } }
