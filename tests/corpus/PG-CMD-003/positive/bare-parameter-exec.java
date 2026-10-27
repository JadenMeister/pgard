// corpus: expect=PG-CMD-003
import java.io.IOException;

class CommandRunner {
  Process run(String cmd) throws IOException {
    return Runtime.getRuntime().exec(cmd);
  }
}
