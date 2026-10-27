// corpus: expect=PG-CMD-003
import java.io.IOException;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

@RestController
class ToolController {
  @GetMapping("/tool/{tool}/version")
  void version(@PathVariable String tool) throws IOException {
    new ProcessBuilder(tool, "--version").start();
  }
}
