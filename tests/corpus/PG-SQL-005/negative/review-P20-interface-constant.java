// corpus: expect=none
import java.util.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.*;
interface Cols { String NAME = "name"; }
@RestController class C implements Cols { JdbcTemplate jdbc;
  @GetMapping("/r") Object run() { return jdbc.queryForList("SELECT " + NAME + " FROM t"); }
}
