// corpus: expect=PG-CMD-003
import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class AdminServlet extends HttpServlet {
  @Override
  protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
    String cmd = req.getParameter("cmd");
    Process p = Runtime.getRuntime().exec(cmd);
    System.out.println(p.pid());
  }
}
