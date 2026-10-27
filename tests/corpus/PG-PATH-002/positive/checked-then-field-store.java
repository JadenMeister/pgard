// corpus: expect=PG-PATH-002
import java.io.File;
import java.io.IOException;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
class CurrentFileController {
  private final File base = new File("/srv/files");
  private File current;

  @PostMapping("/select")
  void select(@RequestParam String name) throws IOException {
    File f = new File(base, name).getCanonicalFile();
    if (!f.getPath().startsWith(base.getCanonicalPath())) {
      throw new IOException("outside the base directory");
    }
    current = f;
  }
}
