// corpus: expect=PG-PATH-002
import java.nio.file.Path;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
class ReadOnlyController {
  private final Path base = Path.of("/srv/files").toAbsolutePath().normalize();

  @PostMapping("/readonly")
  boolean readOnly(@RequestParam String name) {
    Path p = base.resolve(name).normalize();
    if (!p.startsWith(base)) {
      throw new SecurityException("outside the base directory");
    }
    return p.toFile().setReadOnly();
  }
}
