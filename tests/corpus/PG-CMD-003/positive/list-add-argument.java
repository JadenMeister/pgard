// corpus: expect=PG-CMD-003
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
class ConvertController {
  @PostMapping("/convert")
  void convert(@RequestParam String file) throws IOException {
    List<String> cmd = new ArrayList<>();
    cmd.add("convert");
    cmd.add(file);
    cmd.add("out.png");
    new ProcessBuilder(cmd).start();
  }
}
