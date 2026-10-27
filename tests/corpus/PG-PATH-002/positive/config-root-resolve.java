// corpus: expect=PG-PATH-002
import java.nio.file.Files;
import java.nio.file.Path;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
class ExportDownloadController {
  interface Storage { Path getExportRoot(); }

  private final Storage storage;

  ExportDownloadController(Storage storage) { this.storage = storage; }

  @GetMapping("/exports/download")
  byte[] download(@RequestParam String file) throws Exception {
    return Files.readAllBytes(storage.getExportRoot().resolve(file));
  }
}
