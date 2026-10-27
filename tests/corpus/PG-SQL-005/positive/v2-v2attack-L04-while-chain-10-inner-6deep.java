// corpus: expect=PG-SQL-005
import java.util.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.*;
@RestController class C { JdbcTemplate jdbc;
  @GetMapping("/r") void r(@RequestParam String s) {
    String a1="x",a2="x",a3="x",a4="x",a5="x",a6="x",a7="x",a8="x",a9="x",a10="x";
    while (true) { while (true) { while (true) { while (true) { while (true) { while (true) { while (true) {
      jdbc.queryForList("SELECT * FROM t ORDER BY " + a1);
      a1=a2; a2=a3; a3=a4; a4=a5; a5=a6; a6=a7; a7=a8; a8=a9; a9=a10; a10=s;
    } } } } } } }
  }
}
