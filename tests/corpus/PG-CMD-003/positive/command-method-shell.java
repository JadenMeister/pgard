// corpus: expect=PG-CMD-003
import java.io.IOException;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
class JobController {
  @PostMapping("/job")
  void job(@RequestParam String script) throws IOException {
    ProcessBuilder pb = new ProcessBuilder();
    pb.command("/bin/sh", "-c", script);
    pb.start();
  }
}
