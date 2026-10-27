// corpus: expect=none
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.*;
import java.nio.charset.StandardCharsets;

public class Sample {
  org.springframework.security.crypto.password.PasswordEncoder encoder() {
    return new org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder();
  }
}
