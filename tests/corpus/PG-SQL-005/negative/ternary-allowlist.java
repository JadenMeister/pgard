// corpus: expect=low
import java.util.List;
import javax.servlet.http.HttpServletRequest;
import org.springframework.jdbc.core.JdbcTemplate;

class DirectionDao {
  private static final List<String> DIRECTIONS = List.of("asc", "desc");
  private JdbcTemplate jdbc;

  Object list(HttpServletRequest request) {
    String dir = request.getParameter("dir");
    String safe = DIRECTIONS.contains(dir) ? dir : "asc";
    return jdbc.queryForList("SELECT * FROM events ORDER BY created_at " + safe);
  }
}
