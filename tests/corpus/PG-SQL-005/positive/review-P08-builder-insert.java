// corpus: expect=PG-SQL-005
import java.util.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.*;
@RestController class C { JdbcTemplate jdbc;
  @GetMapping("/a") Object a(@RequestParam String table) {
    StringBuilder sql = new StringBuilder(" WHERE 1=1");
    sql.insert(0, "SELECT * FROM " + table);
    return jdbc.queryForList(sql.toString());
  } }
