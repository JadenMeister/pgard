// corpus: expect=none
import java.util.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.*;
enum SortCol { ID, NAME }
@RestController class C { JdbcTemplate jdbc;
  @GetMapping("/r") Object run(@RequestParam String sort) { return jdbc.queryForList("SELECT * FROM t ORDER BY " + SortCol.valueOf(sort.toUpperCase()).name()); }
}
