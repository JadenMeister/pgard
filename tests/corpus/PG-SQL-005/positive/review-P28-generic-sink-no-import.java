// corpus: expect=PG-SQL-005
import java.util.*;
import org.springframework.web.bind.annotation.*;
@RestController class C extends BaseDao {
  @GetMapping("/r") Object run(@RequestParam String n) { return jdbc.queryForList("SELECT * FROM t WHERE n = '" + n + "'"); }
}
