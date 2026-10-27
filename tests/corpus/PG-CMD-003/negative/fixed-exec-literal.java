// corpus: expect=none
import java.io.IOException;

class Uptime {
  String run() throws IOException {
    Process p = Runtime.getRuntime().exec("uptime");
    return new String(p.getInputStream().readAllBytes());
  }
}
