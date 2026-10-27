// corpus: expect=PG-PATH-002
import java.io.FileWriter;
import java.io.IOException;
import javax.servlet.http.HttpServletRequest;

class AuditLog {
  void write(HttpServletRequest request, String line) throws IOException {
    String user = request.getHeader("X-User");
    try (FileWriter writer = new FileWriter("/var/log/audit/" + user + ".log", true)) {
      writer.write(line);
    }
  }
}
