// corpus: expect=PG-SSRF-002
import java.io.IOException;
import java.io.PrintWriter;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.net.URL;

public class Proxy extends HttpServlet {
  @Override
  protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
    String target = req.getParameter("target");
    resp.getOutputStream().write(new URL(target).openStream().readAllBytes());
  }
}
