// corpus: expect=PG-CMD-003
import java.io.IOException;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
class ExportController {
  @GetMapping("/export")
  void export(@RequestParam String url, @RequestParam String out) throws IOException {
    String command = String.format("wkhtmltopdf %s /tmp/%s.pdf", url, out);
    Runtime.getRuntime().exec(command);
  }
}
