// corpus: expect=none
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.*;
import java.nio.charset.StandardCharsets;

public class Sample {
  void signup(SignupRequest dto, UserRepository userRepository, PasswordEncoder encoder) {
    String hash = encoder.encode(dto.getPassword());
    User user = new User();
    user.setPassword(hash);
    userRepository.save(user);
  }
}
