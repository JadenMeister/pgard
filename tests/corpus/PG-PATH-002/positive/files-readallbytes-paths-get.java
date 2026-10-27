// corpus: expect=PG-PATH-002
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

@RestController
class DocumentController {
  @GetMapping("/docs/{name}")
  byte[] doc(@PathVariable String name) throws IOException {
    return Files.readAllBytes(Paths.get("/srv/docs", name));
  }
}
