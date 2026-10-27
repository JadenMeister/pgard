// corpus: expect=low
import javax.servlet.http.HttpServletRequest;
import org.springframework.jdbc.core.JdbcTemplate;

class PageDao {
  private JdbcTemplate jdbc;

  Object page(HttpServletRequest request) {
    int limit = Integer.parseInt(request.getParameter("limit"));
    long offset = Long.valueOf(request.getParameter("offset"));
    return jdbc.queryForList("SELECT * FROM posts LIMIT " + limit + " OFFSET " + offset);
  }
}
