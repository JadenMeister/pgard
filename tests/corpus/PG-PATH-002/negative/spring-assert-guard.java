// corpus: expect=low
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import org.springframework.util.Assert;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
class SpringAssertController {
  private final Path base = Path.of("/srv/files").toAbsolutePath().normalize();

  @GetMapping("/file")
  void file(@RequestParam String name) throws IOException {
    Path p = base.resolve(name).normalize();
    Assert.isTrue(p.startsWith(base), "outside the base directory");
    Files.readString(p);
  }
}
