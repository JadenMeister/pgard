// corpus: expect=PG-PATH-002
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import org.apache.commons.compress.archivers.tar.TarArchiveEntry;
import org.apache.commons.compress.archivers.tar.TarArchiveInputStream;

class TarExtractor {
  void extract(InputStream in, File dest) throws IOException {
    TarArchiveInputStream tar = new TarArchiveInputStream(in);
    TarArchiveEntry entry;
    while ((entry = tar.getNextTarEntry()) != null) {
      File out = new File(dest, entry.getName());
      Files.copy(tar, out.toPath());
    }
  }
}
