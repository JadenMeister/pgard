// corpus: expect=low
import java.io.IOException;
import javax.servlet.http.HttpServletRequest;

class Tail {
  void tail(HttpServletRequest request) throws IOException {
    int lines = Integer.parseInt(request.getParameter("n"));
    new ProcessBuilder("tail", "-n", String.valueOf(lines), "/var/log/app.log").start();
  }
}
