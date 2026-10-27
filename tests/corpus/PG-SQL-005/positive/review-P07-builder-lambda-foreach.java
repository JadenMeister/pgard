// corpus: expect=PG-SQL-005
import java.util.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.*;
@RestController class C { JdbcTemplate jdbc;
  @GetMapping("/a") Object a(@RequestParam List<String> cols) {
    StringBuilder sql = new StringBuilder("SELECT id");
    cols.forEach(c -> sql.append(", ").append(c));
    sql.append(" FROM t");
    return jdbc.queryForList(sql.toString());
  } }
