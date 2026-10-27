// corpus: expect=PG-SQL-005
import java.util.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.*;
@RestController class C { JdbcTemplate jdbc;
  static String TABLE = "t";
  static { TABLE = System.getenv("TABLE"); }
  @GetMapping("/r") Object run() { return jdbc.queryForList("SELECT * FROM " + TABLE); }
}
