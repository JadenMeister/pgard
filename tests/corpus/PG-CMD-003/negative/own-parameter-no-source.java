// corpus: expect=low
import java.io.IOException;

class Thumbs {
  void make(String dir, String name) throws IOException {
    new ProcessBuilder("sh", "-c", "convert " + dir + "/" + name + " thumb.png").start();
  }
}
