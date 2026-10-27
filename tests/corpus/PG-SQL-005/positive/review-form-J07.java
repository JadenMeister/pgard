// corpus: expect=PG-SQL-005
import java.util.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.*;
// form: if (q != null) STMT else return;
@RestController class C { JdbcTemplate jdbc;
  @GetMapping("/a") void a(@RequestParam String q) {
    if (q != null) jdbc.execute("DELETE FROM t WHERE n = '" + q + "'"); else return;
  }
}
