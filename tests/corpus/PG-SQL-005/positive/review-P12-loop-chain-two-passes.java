// corpus: expect=PG-SQL-005
import java.util.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.*;
@RestController class C { JdbcTemplate jdbc;
  @PostMapping("/a") void a(@RequestBody List<String> names) {
    String prev = "none";
    String cur = "none";
    for (String n : names) {
      jdbc.update("INSERT INTO pairs(a) VALUES ('" + prev + "')");
      prev = cur;
      cur = n;
    }
  } }
