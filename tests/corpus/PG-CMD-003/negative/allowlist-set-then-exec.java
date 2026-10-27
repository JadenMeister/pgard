// corpus: expect=low
import java.io.IOException;
import java.util.Set;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
class SafeToolController {
  private static final Set<String> TOOLS = Set.of("gzip", "bzip2", "xz");

  @GetMapping("/tool")
  void run(@RequestParam String tool) throws IOException {
    if (!TOOLS.contains(tool)) {
      throw new IllegalArgumentException("unknown tool");
    }
    Runtime.getRuntime().exec(tool);
  }
}
