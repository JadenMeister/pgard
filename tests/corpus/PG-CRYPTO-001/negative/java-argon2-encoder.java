// corpus: expect=none
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.*;
import java.nio.charset.StandardCharsets;

public class Sample {
  String hash(String password) {
    return new org.springframework.security.crypto.argon2.Argon2PasswordEncoder(16, 32, 1, 1 << 12, 3).encode(password);
  }
}
