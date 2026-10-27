// corpus: expect=PG-SQL-005
import java.util.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.*;
// form: do { STMT } while (false);
@RestController class C { JdbcTemplate jdbc;
  @GetMapping("/a") void a(@RequestParam String q) {
    do { jdbc.execute("DELETE FROM t WHERE n = '" + q + "'"); } while (false);
  }
}
