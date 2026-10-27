// corpus: expect=none
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.*;
import java.nio.charset.StandardCharsets;

public class Sample {
  void rename(long id, String name, UserRepository userRepository) {
    User user = userRepository.findById(id).orElseThrow();
    user.setName(name);
    userRepository.save(user);
  }
}
