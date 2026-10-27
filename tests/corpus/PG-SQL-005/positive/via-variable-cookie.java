// corpus: expect=PG-SQL-005
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import org.springframework.jdbc.core.JdbcTemplate;

class PrefsDao {
  private JdbcTemplate jdbc;

  String theme(HttpServletRequest request) {
    String user = null;
    for (Cookie c : request.getCookies()) {
      if (c.getName().equals("user")) {
        user = c.getValue();
      }
    }
    String where = " WHERE owner = '" + user + "'";
    return jdbc.queryForObject("SELECT theme FROM prefs" + where, String.class);
  }
}
