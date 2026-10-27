// corpus: expect=none
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.*;
import java.nio.charset.StandardCharsets;

public class Sample {
  void signup(SignupRequest dto, UserRepository userRepository) {
    User user = new User();
    user.setPassword(org.springframework.security.crypto.factory.PasswordEncoderFactories.createDelegatingPasswordEncoder().encode(dto.getPassword()));
    userRepository.save(user);
  }
}
