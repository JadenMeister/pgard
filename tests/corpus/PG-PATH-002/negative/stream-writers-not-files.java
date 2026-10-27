// corpus: expect=none
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintWriter;
import javax.servlet.http.HttpServletResponse;

class Responder {
  void write(HttpServletResponse response, OutputStream out) throws IOException {
    PrintWriter writer = new PrintWriter(response.getWriter());
    PrintWriter other = new PrintWriter(out);
    writer.println("ok");
    other.flush();
  }
}
