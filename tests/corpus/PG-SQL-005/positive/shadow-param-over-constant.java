// corpus: expect=PG-SQL-005
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
class CleanupController {
  static final String ORDER_BY = " ORDER BY created_at";
  Connection connection;

  @PostMapping("/cleanup")
  void cleanup(@RequestParam String ORDER_BY) throws SQLException {
    try (Statement st = connection.createStatement()) {
      st.execute("DELETE FROM jobs WHERE done = 1" + ORDER_BY);
    }
  }
}
