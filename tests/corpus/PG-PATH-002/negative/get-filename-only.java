// corpus: expect=low
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
class FileNameOnlyController {
  private final Path base = Paths.get("/srv/public");

  @GetMapping("/f")
  byte[] f(@RequestParam String name) throws IOException {
    Path leaf = Paths.get(name).getFileName();
    return Files.readAllBytes(base.resolve(leaf));
  }
}
