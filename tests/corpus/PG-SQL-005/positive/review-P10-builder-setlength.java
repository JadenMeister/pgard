// corpus: expect=PG-SQL-005
import java.util.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.*;
@RestController class C { JdbcTemplate jdbc;
  @GetMapping("/a") Object a(@RequestParam String sort) {
    StringBuilder sql = new StringBuilder("SELECT * FROM t ORDER BY ");
    sql.append(sort).append(",");
    sql.setLength(sql.length() - 1);
    return jdbc.queryForList(sql.toString());
  } }
