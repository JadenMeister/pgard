// corpus: expect=PG-CRYPTO-003
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.*;
import java.nio.charset.StandardCharsets;

public class Sample {
  private static final Random RND = new Random();
  SecretKey key() {
    byte[] b = new byte[16];
    RND.nextBytes(b);
    return new SecretKeySpec(b, "AES");
  }
}
