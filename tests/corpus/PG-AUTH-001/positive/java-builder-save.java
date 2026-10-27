// corpus: expect=PG-AUTH-001
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.*;
import java.nio.charset.StandardCharsets;

public class Sample {
  void signup(SignupRequest req, UserRepository userRepository) {
    userRepository.save(User.builder().email(req.getEmail()).password(req.getPassword()).build());
  }
}
