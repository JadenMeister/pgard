// corpus: expect=PG-PATH-002
import org.springframework.core.io.Resource;
import org.springframework.core.io.UrlResource;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
class FileResourceController {
  @GetMapping("/res")
  Resource res(@RequestParam String name) throws Exception {
    return new UrlResource("file:/srv/files/" + name);
  }
}
