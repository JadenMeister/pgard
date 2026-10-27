// corpus: expect=PG-PATH-002
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
class AttachmentController {
  private final Path root = Path.of("/data/attachments");

  @GetMapping("/attachment")
  InputStream attachment(@RequestParam String id) throws IOException {
    Path file = root.resolve(id);
    return Files.newInputStream(file);
  }
}
