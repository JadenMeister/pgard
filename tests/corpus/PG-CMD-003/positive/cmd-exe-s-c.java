// corpus: expect=PG-CMD-003
import java.io.IOException;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
class WindowsTypeController {
  @GetMapping("/type")
  void type(@RequestParam String file) throws IOException {
    new ProcessBuilder("cmd.exe", "/S", "/C", "type " + file).start();
  }
}
