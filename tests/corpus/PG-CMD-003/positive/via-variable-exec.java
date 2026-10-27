// corpus: expect=PG-CMD-003
import java.io.IOException;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
class DiskController {
  @GetMapping("/du")
  void usage(@RequestParam String dir) throws IOException {
    String cmd = "du -sh ";
    cmd += dir;
    Runtime runtime = Runtime.getRuntime();
    runtime.exec(cmd);
  }
}
