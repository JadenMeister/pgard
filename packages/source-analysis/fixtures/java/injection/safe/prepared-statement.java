import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import javax.servlet.http.HttpServletRequest;

class UserLookup {
  ResultSet byName(Connection connection, HttpServletRequest request) throws SQLException {
    PreparedStatement statement = connection.prepareStatement("SELECT * FROM users WHERE name = ?");
    statement.setString(1, request.getParameter("name"));
    return statement.executeQuery();
  }
}
