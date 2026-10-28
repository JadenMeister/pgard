// corpus: expect=none
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.*;
import java.nio.charset.StandardCharsets;

public class Sample {
  String hash(String password) {
    return new org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder().encode(password);
  }
}
