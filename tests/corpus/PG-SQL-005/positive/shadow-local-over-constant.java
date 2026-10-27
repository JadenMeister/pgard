// corpus: expect=PG-SQL-005
import javax.servlet.http.HttpServletRequest;
import org.springframework.jdbc.core.JdbcTemplate;

class ExportDao {
  private static final String TABLE = "exports";
  private JdbcTemplate jdbc;

  int rows(HttpServletRequest request) {
    // The local TABLE shadows the constant: it is request input, not the literal above.
    String TABLE = request.getParameter("table");
    return jdbc.queryForObject("SELECT COUNT(*) FROM " + TABLE, Integer.class);
  }
}
