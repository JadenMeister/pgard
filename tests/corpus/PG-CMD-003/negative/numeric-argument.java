// corpus: expect=low
import java.io.IOException;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
class PingController {
  @GetMapping("/ping")
  void ping(@RequestParam int count) throws IOException {
    Runtime.getRuntime().exec("ping -c " + count + " 127.0.0.1");
  }
}
