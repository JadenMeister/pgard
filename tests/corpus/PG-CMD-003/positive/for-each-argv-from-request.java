// corpus: expect=PG-CMD-003
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import javax.servlet.http.HttpServletRequest;

class ZipTool {
  void zip(HttpServletRequest request) throws IOException {
    List<String> argv = new ArrayList<>();
    argv.add("zip");
    argv.add("archive.zip");
    for (String name : request.getParameterValues("files")) {
      argv.add(name);
    }
    new ProcessBuilder(argv).start();
  }
}
