// corpus: expect=low
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
class GuardedController {
  private final Path base = Path.of("/srv/files").toAbsolutePath().normalize();

  @GetMapping("/file")
  byte[] file(@RequestParam String name) throws IOException {
    Path p = base.resolve(name).normalize();
    if (!p.startsWith(base)) {
      throw new IllegalArgumentException("outside the base directory");
    }
    return Files.readAllBytes(p);
  }
}
