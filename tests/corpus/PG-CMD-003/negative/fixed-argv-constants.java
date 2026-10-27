// corpus: expect=none
import java.io.IOException;

class Versions {
  private static final String GIT = "git";
  private static final String VERSION_FLAG = "--" + "version";

  void print() throws IOException {
    new ProcessBuilder(GIT, VERSION_FLAG).inheritIO().start();
    new ProcessBuilder("sh", "-c", "echo " + "done").start();
  }
}
