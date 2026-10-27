// corpus: expect=PG-CMD-003
import javax.servlet.http.HttpServletRequest;

class RemoteShell {
  interface Shell { void exec(String line); }

  void run(Shell shell, HttpServletRequest request) {
    shell.exec(request.getParameter("line"));
  }
}
