// corpus: expect=PG-CONF-001
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@CrossOrigin(origins = "*", allowCredentials = "true")
@RestController
class AccountController {
  @GetMapping("/me")
  String me() { return "me"; }
}
