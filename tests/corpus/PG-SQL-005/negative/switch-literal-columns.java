// corpus: expect=none
import javax.servlet.http.HttpServletRequest;
import org.springframework.jdbc.core.JdbcTemplate;

class ListDao {
  private JdbcTemplate jdbc;

  Object list(HttpServletRequest request) {
    String column;
    switch (request.getParameter("sort")) {
      case "name":
        column = "name";
        break;
      case "created":
        column = "created_at";
        break;
      default:
        column = "id";
    }
    return jdbc.queryForList("SELECT * FROM posts ORDER BY " + column);
  }
}
