// corpus: expect=low
import java.io.File;

class FileHelper {
  File child(File dir, String name) {
    return new File(dir, name);
  }
}
