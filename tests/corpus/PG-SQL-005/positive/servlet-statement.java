// corpus: expect=PG-SQL-005
import java.io.IOException;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class AccountServlet extends HttpServlet {
  @Override
  protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
    String id = request.getParameter("id");
    try (Connection conn = Db.open(); Statement st = conn.createStatement()) {
      ResultSet rs = st.executeQuery("SELECT * FROM accounts WHERE id = " + id);
      while (rs.next()) {
        response.getWriter().println(rs.getString("owner"));
      }
    } catch (SQLException e) {
      throw new IOException(e);
    }
  }
}
