// corpus: expect=low
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

class SafeUnzipper {
  void unzip(InputStream archive, File destDir) throws IOException {
    String root = destDir.getCanonicalPath();
    try (ZipInputStream zis = new ZipInputStream(archive)) {
      ZipEntry entry;
      while ((entry = zis.getNextEntry()) != null) {
        File out = new File(destDir, entry.getName());
        if (!out.getCanonicalPath().startsWith(root + File.separator)) {
          throw new IOException("Zip Slip: " + entry.getName());
        }
        try (FileOutputStream fos = new FileOutputStream(out)) {
          zis.transferTo(fos);
        }
      }
    }
  }
}
