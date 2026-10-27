// corpus: expect=PG-SQL-005
import java.util.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.*;
@RestController class C { JdbcTemplate jdbc;
  @GetMapping("/a") Object a(@RequestParam String sort) {
    String col = "id";
    try { Integer.parseInt(sort); } catch (NumberFormatException e) { col = sort; }
    return jdbc.queryForList("SELECT * FROM t ORDER BY " + col);
  } }
