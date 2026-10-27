// corpus: expect=PG-CMD-003
import java.io.IOException;
import java.util.Arrays;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
class ScriptController {
  @PostMapping("/run")
  void run(@RequestBody String script) throws IOException {
    new ProcessBuilder(Arrays.asList("bash", "-c", script)).inheritIO().start();
  }
}
