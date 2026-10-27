// corpus: expect=none
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.*;
import java.nio.charset.StandardCharsets;

public class Sample {
  void touch(User user, UserRepository userRepository) {
    user.setPassword(user.getPassword());
    userRepository.save(user);
  }
}
