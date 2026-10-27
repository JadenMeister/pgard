// corpus: expect=low
import java.io.IOException;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
class HelperController {
  @GetMapping("/run")
  void run(@RequestParam String name) throws IOException {
    String command = buildCommand(name);
    Runtime.getRuntime().exec(command);
  }

  private String buildCommand(String name) {
    return "run-job " + name.replaceAll("[^a-z]", "");
  }
}
