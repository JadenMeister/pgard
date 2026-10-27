// corpus: expect=PG-SQL-005
import java.util.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.*;
@RestController class C { JdbcTemplate jdbc; StringBuilder current;
  void addOrder(String col) { current.append(" ORDER BY ").append(col); }
  @GetMapping("/a") Object a(@RequestParam String sort) {
    StringBuilder sql = new StringBuilder("SELECT * FROM t");
    this.current = sql;
    addOrder(sort);
    return jdbc.queryForList(sql.toString());
  } }
