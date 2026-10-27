// corpus: expect=PG-SQL-005
import java.util.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.*;
@RestController class C { JdbcTemplate repo;
  @GetMapping("/r") Object run(@RequestParam String t) { String q = base() + t; return repo.queryForList(q); }
  String base() { return "x"; }
}
