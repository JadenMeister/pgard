// corpus: expect=PG-CMD-003
import java.io.IOException;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
class DiagController {
  @GetMapping("/ping")
  String ping(@RequestParam String host) throws IOException {
    Process p = Runtime.getRuntime().exec("ping -c 1 " + host);
    return "started " + p.pid();
  }
}
