// corpus: expect=PG-CMD-003
import javax.servlet.http.HttpServletRequest;

class StaticShell {
  static void exec(String line) {}

  void run(HttpServletRequest request) {
    StaticShell.exec("sh -c " + request.getParameter("c"));
  }
}
