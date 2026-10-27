// corpus: expect=PG-PATH-002
import java.io.File;
import net.lingala.zip4j.ZipFile;
import net.lingala.zip4j.model.FileHeader;

class Zip4jExtractor {
  void extract(ZipFile zip, File dest) throws Exception {
    for (FileHeader header : zip.getFileHeaders()) {
      File out = new File(dest, header.getFileName());
      out.getParentFile().mkdirs();
    }
  }
}
