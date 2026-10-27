// corpus: expect=PG-SQL-005
import java.sql.*;
import javax.servlet.http.*;
class S extends HttpServlet {
  Connection conn;
  protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws Exception {
    String[] ids = req.getParameterValues("id");
    rows:
    for (String id : ids) {
      conn.createStatement().executeUpdate("DELETE FROM t WHERE id = '" + id + "'");
    }
  }
}
