// corpus: expect=low
import java.io.IOException;
import java.util.List;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
class ReportController {
  private static final List<String> REPORTS = List.of("daily", "weekly");

  @GetMapping("/report")
  void report(@RequestParam String name) throws IOException {
    if (!REPORTS.contains(name)) {
      return;
    }
    new ProcessBuilder("sh", "-c", "make-report " + name).start();
  }
}
