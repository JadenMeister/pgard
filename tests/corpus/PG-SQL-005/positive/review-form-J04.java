// corpus: expect=PG-SQL-005
import java.util.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.*;
// form: Runnable r = () -> { STMT }; r.run();
@RestController class C { JdbcTemplate jdbc;
  @GetMapping("/a") void a(@RequestParam String q) {
    Runnable r = () -> { jdbc.execute("DELETE FROM t WHERE n = '" + q + "'"); }; r.run();
  }
}
