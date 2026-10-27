// corpus: expect=PG-SQL-005
import java.util.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.*;
// form: Optional.of(q).ifPresent(v -> { STMT });
@RestController class C { JdbcTemplate jdbc;
  @GetMapping("/a") void a(@RequestParam String q) {
    Optional.of(q).ifPresent(v -> { jdbc.execute("DELETE FROM t WHERE n = '" + q + "'"); });
  }
}
