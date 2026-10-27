// corpus: expect=PG-AUTH-001
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.*;
import java.nio.charset.StandardCharsets;

public class Sample {
  void register(String email, String password, UserRepository repo) {
    User u = new User();
    u.setPassword(password);
    repo.save(u);
  }
}
