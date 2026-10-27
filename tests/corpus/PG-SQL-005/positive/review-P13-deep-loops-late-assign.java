// corpus: expect=PG-SQL-005
import java.util.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.*;
@RestController class C { JdbcTemplate jdbc;
  @GetMapping("/a") void a(@RequestParam String sort) {
    String col = "id";
    for (int a = 0; a < 2; a++) { for (int b = 0; b < 2; b++) { for (int c = 0; c < 2; c++) { for (int d = 0; d < 2; d++) { for (int e = 0; e < 2; e++) {
      jdbc.queryForList("SELECT * FROM t ORDER BY " + col);
      col = sort;
    } } } } }
  } }
