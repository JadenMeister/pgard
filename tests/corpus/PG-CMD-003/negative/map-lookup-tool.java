// corpus: expect=low
import java.io.IOException;
import java.util.Map;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
class ToolTableController {
  private static final Map<String, String> TOOLS = Map.of("gz", "gzip", "bz", "bzip2");

  @GetMapping("/tool")
  void run(@RequestParam String kind) throws IOException {
    String tool = TOOLS.get(kind);
    new ProcessBuilder(tool, "-t", "/data/a.tar").start();
  }
}
