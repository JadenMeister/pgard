// corpus: expect=none
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import javax.servlet.http.HttpServletRequest;

class LoginDao {
  ResultSet find(Connection connection, HttpServletRequest request) throws SQLException {
    PreparedStatement ps =
        connection.prepareStatement("SELECT id FROM users WHERE name = ? AND password_hash = ?");
    ps.setString(1, request.getParameter("name"));
    ps.setString(2, request.getParameter("hash"));
    return ps.executeQuery();
  }
}
