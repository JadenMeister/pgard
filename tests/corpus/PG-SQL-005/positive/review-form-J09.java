// corpus: expect=PG-SQL-005
import java.util.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.*;
// form: for (int i = 0; i < 1; i++) STMT
@RestController class C { JdbcTemplate jdbc;
  @GetMapping("/a") void a(@RequestParam String q) {
    for (int i = 0; i < 1; i++) jdbc.execute("DELETE FROM t WHERE n = '" + q + "'");
  }
}
