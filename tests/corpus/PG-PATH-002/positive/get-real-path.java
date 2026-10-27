// corpus: expect=PG-PATH-002
import java.io.File;
import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class AssetServlet extends HttpServlet {
  @Override
  protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
    String name = request.getParameter("asset");
    String real = getServletContext().getRealPath("/assets/" + name);
    response.getOutputStream().write(java.nio.file.Files.readAllBytes(new File(real).toPath()));
  }
}
