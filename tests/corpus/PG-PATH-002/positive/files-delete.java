// corpus: expect=PG-PATH-002
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

@RestController
class CleanupController {
  @DeleteMapping("/tmp/{name}")
  void delete(@PathVariable String name) throws IOException {
    Files.deleteIfExists(Paths.get("/tmp/exports/" + name));
  }
}
