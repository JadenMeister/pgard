// corpus: expect=none
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.*;
import java.nio.charset.StandardCharsets;

public class Sample {
  boolean login(LoginRequest req, User user, PasswordEncoder passwordEncoder) {
    return passwordEncoder.matches(req.getPassword(), user.getPassword());
  }
}
