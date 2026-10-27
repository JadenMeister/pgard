// corpus: expect=PG-PATH-002
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
class WrongGuardController {
  private final Path base = Path.of("/srv/files").toAbsolutePath().normalize();

  @GetMapping("/file")
  byte[] file(@RequestParam String name, @RequestParam String other) throws IOException {
    Path checked = base.resolve(other).normalize();
    if (!checked.startsWith(base)) {
      throw new IllegalArgumentException("bad path");
    }
    return Files.readAllBytes(base.resolve(name));
  }
}
