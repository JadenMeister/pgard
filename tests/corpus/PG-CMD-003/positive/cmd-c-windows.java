// corpus: expect=PG-CMD-003
import java.io.IOException;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
class DirController {
  @GetMapping("/dir")
  void list(@RequestParam String path) throws IOException {
    ProcessBuilder pb = new ProcessBuilder("cmd.exe", "/c", "dir " + path);
    pb.start();
  }
}
