// corpus: expect=PG-PATH-002
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
class NaiveGuardController {
  private final Path base = Path.of("/srv/files");

  @GetMapping("/file")
  byte[] file(@RequestParam String name) throws IOException {
    Path p = base.resolve(name);
    if (!p.startsWith(base)) {
      throw new IllegalArgumentException("bad path");
    }
    return Files.readAllBytes(p);
  }
}
