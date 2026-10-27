// corpus: expect=PG-PATH-002
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

class Unzipper {
  void unzip(InputStream archive, File destDir) throws IOException {
    try (ZipInputStream zis = new ZipInputStream(archive)) {
      ZipEntry entry;
      while ((entry = zis.getNextEntry()) != null) {
        File out = new File(destDir, entry.getName());
        try (FileOutputStream fos = new FileOutputStream(out)) {
          zis.transferTo(fos);
        }
      }
    }
  }
}
