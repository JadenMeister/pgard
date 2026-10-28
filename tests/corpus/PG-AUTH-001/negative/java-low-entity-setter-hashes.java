// corpus: expect=low
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.*;
import java.nio.charset.StandardCharsets;

public class Sample {
  void signup(String email, String password, UserRepository repo) {
    User u = new User();
    u.setEmail(email);
    u.setPassword(password); // User#setPassword hashes with BCrypt
    repo.save(u);
  }
}
