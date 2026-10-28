// corpus: expect=PG-AUTH-001
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.*;
import java.nio.charset.StandardCharsets;

public class Sample {
  void signup(SignupRequest dto, UserRepository userRepository) {
    String password = dto.getPassword();
    User user = new User();
    user.setPassword(password);
    userRepository.save(user);
  }
}
