// corpus: expect=PG-SQL-005
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;

class SessionStore {
  PreparedStatement lookup(Connection connection, String token) throws SQLException {
    // The statement is prepared, but the token is part of the SQL text, not a parameter.
    PreparedStatement ps = connection.prepareStatement("SELECT user_id FROM sessions WHERE token = '" + token + "'");
    return ps;
  }
}
