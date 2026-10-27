// corpus: expect=PG-CMD-003
import java.io.IOException;
import java.util.Set;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
class MixedController {
  private static final Set<String> TOOLS = Set.of("gzip", "bzip2");

  @GetMapping("/pack")
  void pack(@RequestParam String tool, @RequestParam String file) throws IOException {
    if (!TOOLS.contains(tool)) {
      throw new IllegalArgumentException("tool");
    }
    Runtime.getRuntime().exec(tool + " " + file);
  }
}
