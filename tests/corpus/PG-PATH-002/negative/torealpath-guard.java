// corpus: expect=low
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import javax.servlet.http.HttpServletRequest;

class RealPathReader {
  private final Path root;

  RealPathReader(Path root) { this.root = root; }

  String read(HttpServletRequest request) throws IOException {
    Path candidate = root.resolve(request.getParameter("p"));
    Path real = candidate.toRealPath();
    if (real.startsWith(root.toRealPath())) {
      return Files.readString(real);
    }
    throw new SecurityException("outside root");
  }
}
