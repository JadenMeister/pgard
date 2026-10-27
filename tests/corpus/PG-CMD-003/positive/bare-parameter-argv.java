// corpus: expect=PG-CMD-003
import java.io.IOException;
import java.util.List;

class ArgvRunner {
  void run(List<String> argv) throws IOException {
    new ProcessBuilder(argv).inheritIO().start();
  }
}
