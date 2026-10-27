// corpus: expect=PG-SQL-005
import java.util.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.*;
final class Col { final String raw; private Col(String r) { raw = r; } static Col valueOf(String s) { return new Col(s); } String name() { return raw; } }
@RestController class C { JdbcTemplate jdbc;
  @GetMapping("/r") Object r(@RequestParam String s) { return jdbc.queryForList("SELECT * FROM t ORDER BY " + Col.valueOf(s).name()); }
}
