// corpus: expect=PG-PATH-002
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.charset.StandardCharsets;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
class ReportExportController {
  @PostMapping("/reports/export")
  void export(@RequestParam String name, @RequestBody String csv) throws IOException {
    Files.writeString(Path.of("/reports", name + ".csv"), csv, StandardCharsets.UTF_8);
  }
}
