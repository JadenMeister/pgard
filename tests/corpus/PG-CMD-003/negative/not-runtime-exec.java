// corpus: expect=low
import javax.servlet.http.HttpServletRequest;

class Dispatcher {
  private final Script script;

  Dispatcher(Script script) { this.script = script; }

  void handle(HttpServletRequest request) {
    String line = request.getParameter("line");
    script.exec(line);
    script.command(line);
  }

  interface Script {
    void exec(String line);
    void command(String line);
  }
}
