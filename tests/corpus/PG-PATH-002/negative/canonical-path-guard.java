// corpus: expect=low
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
class CanonicalController {
  private final File dir = new File("/srv/files");

  @GetMapping("/file")
  FileInputStream file(@RequestParam String name) throws IOException {
    File dest = new File(dir, name);
    String destPath = dest.getCanonicalPath();
    if (!destPath.startsWith(dir.getCanonicalPath() + File.separator)) {
      throw new IOException("entry is outside of the target dir: " + name);
    }
    return new FileInputStream(dest);
  }
}
