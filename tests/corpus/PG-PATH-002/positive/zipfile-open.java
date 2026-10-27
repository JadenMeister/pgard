// corpus: expect=PG-PATH-002
import java.io.IOException;
import java.util.zip.ZipFile;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
class ArchiveListController {
  @GetMapping("/archive")
  int count(@RequestParam String name) throws IOException {
    try (ZipFile zip = new ZipFile("/srv/archives/" + name)) {
      return zip.size();
    }
  }
}
