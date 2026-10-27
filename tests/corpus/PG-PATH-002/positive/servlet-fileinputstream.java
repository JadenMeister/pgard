// corpus: expect=PG-PATH-002
import java.io.FileInputStream;
import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class FileServlet extends HttpServlet {
  @Override
  protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
    try (FileInputStream in = new FileInputStream(req.getParameter("f"))) {
      in.transferTo(resp.getOutputStream());
    }
  }
}
