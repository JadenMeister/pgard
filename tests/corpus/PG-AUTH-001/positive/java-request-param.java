// corpus: expect=PG-AUTH-001
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.*;
import java.nio.charset.StandardCharsets;
import org.springframework.web.bind.annotation.*;

public class Sample {
  void signup(@RequestParam String email, @RequestParam String password, UserRepository userRepository) {
    User user = new User();
    user.setEmail(email);
    user.setPassword(password);
    userRepository.save(user);
  }
}
