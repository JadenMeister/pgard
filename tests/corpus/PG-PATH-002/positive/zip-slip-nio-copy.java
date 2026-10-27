// corpus: expect=PG-PATH-002
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

class ZipExtractor {
  void extract(ZipFile zip, Path target) throws IOException {
    for (ZipEntry entry : java.util.Collections.list(zip.entries())) {
      Path out = target.resolve(entry.getName());
      Files.copy(zip.getInputStream(entry), out);
    }
  }
}
