// corpus: expect=PG-CMD-003
import java.io.IOException;
import org.apache.commons.exec.CommandLine;
import org.apache.commons.exec.DefaultExecutor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
class LookupController {
  @GetMapping("/lookup")
  void lookup(@RequestParam String host) throws IOException {
    CommandLine line = CommandLine.parse("nslookup " + host);
    new DefaultExecutor().execute(line);
  }
}
