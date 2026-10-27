// corpus: expect=PG-SQL-005
import java.util.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.*;
@RestController class C { JdbcTemplate jdbc;
  @GetMapping("/r") void r(@RequestParam String s) {
    String a = "x", b = "x", c = "x";
    for (int i0 = 0; i0 < 2; i0++) { for (int i1 = 0; i1 < 2; i1++) { for (int i2 = 0; i2 < 2; i2++) { for (int i3 = 0; i3 < 2; i3++) { for (int i4 = 0; i4 < 2; i4++) { for (int i5 = 0; i5 < 2; i5++) { for (int i6 = 0; i6 < 2; i6++) { for (int i7 = 0; i7 < 2; i7++) { 
      jdbc.queryForList("SELECT * FROM t ORDER BY " + a);
      a = b; b = c; c = s;
    }}}}}}}}
  }
}
