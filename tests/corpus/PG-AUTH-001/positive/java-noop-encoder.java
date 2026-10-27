// corpus: expect=PG-AUTH-001
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.*;
import java.nio.charset.StandardCharsets;

public class Sample {
  org.springframework.security.crypto.password.PasswordEncoder encoder() {
    return org.springframework.security.crypto.password.NoOpPasswordEncoder.getInstance();
  }
}
