// corpus: expect=none
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.*;
import java.nio.charset.StandardCharsets;

public class Sample {
  SecretKey key() {
    byte[] b = new byte[32];
    new SecureRandom().nextBytes(b);
    return new SecretKeySpec(b, "AES");
  }
}
