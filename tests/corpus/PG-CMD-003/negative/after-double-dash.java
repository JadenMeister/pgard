// corpus: expect=low
import java.io.IOException;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
class GrepController {
  @GetMapping("/grep")
  void grep(@RequestParam String pattern) throws IOException {
    new ProcessBuilder("grep", "-r", "--", pattern, "/var/log/app").start();
  }
}
