// corpus: expect=PG-PATH-002
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class StaticServlet extends HttpServlet {
  private final File base = new File("/srv/static");

  @Override
  protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
    File f = new File(base, request.getPathInfo());
    try (FileInputStream in = new FileInputStream(f)) {
      in.transferTo(response.getOutputStream());
    }
  }
}
