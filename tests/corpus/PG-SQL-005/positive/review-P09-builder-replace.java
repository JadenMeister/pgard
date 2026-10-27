// corpus: expect=PG-SQL-005
import java.util.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.*;
@RestController class C { JdbcTemplate jdbc;
  @GetMapping("/a") Object a(@RequestParam String table) {
    StringBuilder sql = new StringBuilder("SELECT * FROM XXXX");
    sql.replace(14, 18, table);
    return jdbc.queryForList(sql.toString());
  } }
