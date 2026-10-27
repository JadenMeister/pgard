// corpus: expect=PG-SQL-005
import java.util.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.*;
@RestController class C { JdbcTemplate jdbc;
  @GetMapping("/r") Object r(@RequestParam String s) { StringBuilder sb = new StringBuilder("SELECT * FROM t"); StringBuilder alias = (sb); alias.append(" WHERE n = '" + s + "'"); return jdbc.queryForList(sb.toString()); }
}
