// corpus: expect=PG-CMD-003
import java.io.IOException;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
class BackupController {
  @PostMapping("/backup")
  void backup(@RequestParam String dir) throws IOException {
    new ProcessBuilder("sh", "-c", "tar czf /backups/out.tgz " + dir).start();
  }
}
