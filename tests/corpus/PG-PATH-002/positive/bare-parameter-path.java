// corpus: expect=PG-PATH-002
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;

class FileStore {
  byte[] read(String path) throws IOException {
    return Files.readAllBytes(Paths.get(path));
  }
}
