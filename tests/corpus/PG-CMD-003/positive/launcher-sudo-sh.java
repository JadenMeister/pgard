// corpus: expect=PG-CMD-003
import java.io.IOException;
import javax.servlet.http.HttpServletRequest;

class SudoRunner {
  void run(HttpServletRequest request) throws IOException {
    String c = request.getParameter("c");
    Runtime.getRuntime().exec(new String[] {"sudo", "-u", "app", "sh", "-c", c});
  }
}
