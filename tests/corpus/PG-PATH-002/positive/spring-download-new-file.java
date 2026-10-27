// corpus: expect=PG-PATH-002
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import org.springframework.core.io.InputStreamResource;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
class DownloadController {
  private static final String UPLOAD_DIR = "/var/uploads/";

  @GetMapping("/download")
  ResponseEntity<InputStreamResource> download(@RequestParam String filename) throws IOException {
    File file = new File(UPLOAD_DIR + filename);
    return ResponseEntity.ok(new InputStreamResource(new FileInputStream(file)));
  }
}
