// corpus: expect=PG-CMD-003
import java.io.IOException;
import javax.servlet.http.HttpServletRequest;
import org.apache.commons.exec.CommandLine;
import org.apache.commons.exec.DefaultExecutor;

class Thumbnailer {
  void make(HttpServletRequest request) throws IOException {
    String name = request.getParameter("name");
    CommandLine line = new CommandLine("convert");
    line.addArgument(name, false);
    line.addArgument("thumb.png");
    new DefaultExecutor().execute(line);
  }
}
