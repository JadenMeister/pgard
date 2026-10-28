// corpus: expect=none
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
class StatusController {
  @CrossOrigin(origins = "*")
  @GetMapping("/status")
  String status() { return "ok"; }
}
