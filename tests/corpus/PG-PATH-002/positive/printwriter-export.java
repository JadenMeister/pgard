// corpus: expect=PG-PATH-002
import java.io.IOException;
import java.io.PrintWriter;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
class CsvExportController {
  @PostMapping("/export")
  void export(@RequestParam String name) throws IOException {
    try (PrintWriter out = new PrintWriter("/srv/out/" + name)) {
      out.println("id,name");
    }
  }
}
