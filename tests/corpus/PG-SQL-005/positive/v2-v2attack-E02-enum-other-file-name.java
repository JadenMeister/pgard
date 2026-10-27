// corpus: expect=PG-SQL-005
import java.util.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.*;
@RestController class C { JdbcTemplate jdbc;
  Object r(OrderStatus status) { return jdbc.queryForList("SELECT * FROM t WHERE status = '" + status.name() + "'"); }
}
