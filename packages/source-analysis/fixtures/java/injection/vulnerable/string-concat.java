import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import javax.servlet.http.HttpServletRequest;

class UserLookup {
  ResultSet byName(Connection connection, HttpServletRequest request) throws SQLException {
    Statement statement = connection.createStatement();
    return statement.executeQuery("SELECT * FROM users WHERE name = '" + request.getParameter("name") + "'");
  }
}
