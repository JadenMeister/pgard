// corpus: expect=PG-SQL-005
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import javax.servlet.http.HttpServletRequest;

class AuditDao {
  void purge(Connection connection, HttpServletRequest request) throws SQLException {
    String query = "DELETE FROM audit_log WHERE";
    query = query + " tenant = 7";
    query += " AND actor = '" + request.getHeader("X-Actor") + "'";
    try (Statement st = connection.createStatement()) {
      st.executeUpdate(query);
    }
  }
}
