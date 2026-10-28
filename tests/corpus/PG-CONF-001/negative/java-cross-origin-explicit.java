// corpus: expect=none
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@CrossOrigin(origins = "https://app.example.com", allowCredentials = "true")
@RestController
class AccountController {
  @GetMapping("/me")
  String me() { return "me"; }
}
