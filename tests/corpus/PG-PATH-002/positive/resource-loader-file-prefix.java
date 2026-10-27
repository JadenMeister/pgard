// corpus: expect=PG-PATH-002
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
class TemplateController {
  private final ResourceLoader resourceLoader;

  TemplateController(ResourceLoader resourceLoader) { this.resourceLoader = resourceLoader; }

  @GetMapping("/template")
  Resource template(@RequestParam String path) {
    return resourceLoader.getResource("file:" + path);
  }
}
