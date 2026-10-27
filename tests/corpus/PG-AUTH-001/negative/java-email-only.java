// corpus: expect=none
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.*;
import java.nio.charset.StandardCharsets;

public class Sample {
  void signup(SignupRequest dto, UserRepository userRepository) {
    User user = new User();
    user.setEmail(dto.getEmail());
    userRepository.save(user);
  }
}
