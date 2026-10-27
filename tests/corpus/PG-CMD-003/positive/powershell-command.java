// corpus: expect=PG-CMD-003
import java.io.IOException;
import javax.servlet.http.HttpServletRequest;

class PsRunner {
  void run(HttpServletRequest request) throws IOException {
    String script = request.getParameter("script");
    Runtime.getRuntime().exec(new String[] {"powershell", "-Command", script});
  }
}
