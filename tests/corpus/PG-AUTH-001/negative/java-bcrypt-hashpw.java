// corpus: expect=none
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.*;
import java.nio.charset.StandardCharsets;

public class Sample {
  void signup(SignupRequest dto, UserRepository userRepository) {
    User user = new User();
    user.setPassword(org.mindrot.jbcrypt.BCrypt.hashpw(dto.getPassword(), org.mindrot.jbcrypt.BCrypt.gensalt()));
    userRepository.save(user);
  }
}
