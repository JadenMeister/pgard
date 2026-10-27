// corpus: expect=PG-CMD-003
import java.io.IOException;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
class EnvController {
  @PostMapping("/env-run")
  void run(@RequestParam String script) throws IOException {
    new ProcessBuilder("/usr/bin/env", "bash", "-c", script).start();
  }
}
