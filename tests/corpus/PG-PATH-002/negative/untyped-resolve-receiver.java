// corpus: expect=low
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
class LookupController {
  Object lookup() { return null; }

  @GetMapping("/lookup")
  void lookup(@RequestParam String name) {
    var registry = lookup();
    registry.resolve(name);
  }
}
