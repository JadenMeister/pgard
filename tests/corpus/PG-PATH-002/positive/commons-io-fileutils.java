// corpus: expect=PG-PATH-002
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import javax.servlet.http.HttpServletRequest;
import org.apache.commons.io.FileUtils;

class LogReader {
  String read(HttpServletRequest request) throws IOException {
    String name = request.getParameter("log");
    return FileUtils.readFileToString(new File("/var/log/app", name), StandardCharsets.UTF_8);
  }
}
