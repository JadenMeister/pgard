// corpus: expect=none
import javax.servlet.http.HttpServletRequest;

class FixedShell {
  interface Shell { void exec(String line); }

  void run(Shell shell, HttpServletRequest request) {
    shell.exec("status");
    Process p = null;
    p.destroy();
  }
}
