// corpus: expect=PG-CONF-001
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
class AccountController {
  @CrossOrigin(originPatterns = "*", allowCredentials = "true")
  @GetMapping("/me")
  String me() { return "me"; }
}
