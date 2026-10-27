// corpus: expect=low
import java.io.File;
import java.util.Map;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
class TemplateTableController {
  private static final Map<String, String> TEMPLATES = Map.of("a", "invoice.html", "b", "receipt.html");

  @GetMapping("/tpl")
  File tpl(@RequestParam String kind) {
    return new File("/srv/templates", TEMPLATES.get(kind));
  }
}
