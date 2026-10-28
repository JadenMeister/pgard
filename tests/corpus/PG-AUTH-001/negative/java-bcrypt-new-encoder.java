// corpus: expect=none
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.*;
import java.nio.charset.StandardCharsets;

public class Sample {
  void signup(SignupRequest dto, UserRepository userRepository) {
    userRepository.save(new User(dto.getEmail(), new BCryptPasswordEncoder().encode(dto.getPassword())));
  }
}
