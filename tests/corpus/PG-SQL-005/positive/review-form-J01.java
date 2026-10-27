// corpus: expect=PG-SQL-005
import java.util.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.*;
// form: synchronized (this) { STMT }
@RestController class C { JdbcTemplate jdbc;
  @GetMapping("/a") void a(@RequestParam String q) {
    synchronized (this) { jdbc.execute("DELETE FROM t WHERE n = '" + q + "'"); }
  }
}
