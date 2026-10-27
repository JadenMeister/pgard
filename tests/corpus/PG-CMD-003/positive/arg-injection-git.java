// corpus: expect=PG-CMD-003
import java.io.IOException;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
class GitController {
  @GetMapping("/log")
  void log(@RequestParam String ref) throws IOException {
    new ProcessBuilder("git", "log", "--oneline", ref).directory(null).start();
  }
}
