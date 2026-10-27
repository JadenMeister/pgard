// corpus: expect=low
import java.io.IOException;
import java.io.PrintWriter;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class Page extends HttpServlet {
  @Override
  protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
    String name = req.getParameter("name");
    resp.setContentType("text/html");
    if (!name.matches("[A-Za-z ]+")) {
      resp.sendError(400);
      return;
    }
    resp.getWriter().write("<p>" + name + "</p>");
  }
}
