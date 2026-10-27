// corpus: expect=none
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
class TemplateLookupController {
  @GetMapping("/tpl")
  boolean exists(@RequestParam String name) {
    return getClass().getClassLoader().getResource("templates/" + name) != null;
  }
}
