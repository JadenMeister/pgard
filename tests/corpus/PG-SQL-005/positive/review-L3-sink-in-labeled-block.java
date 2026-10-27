// corpus: expect=PG-SQL-005
import java.sql.*;
import javax.servlet.http.*;
class S extends HttpServlet {
  Connection conn;
  protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws Exception {
    String id = req.getParameter("id");
    work: {
      if (id == null) break work;
      conn.createStatement().executeUpdate("DELETE FROM t WHERE id = '" + id + "'");
    }
  }
}
