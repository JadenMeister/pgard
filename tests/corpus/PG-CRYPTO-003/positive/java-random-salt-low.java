// corpus: expect=PG-CRYPTO-003
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.*;
import java.nio.charset.StandardCharsets;

public class Sample {
  private static final Random RNG = new Random();
  byte[] salt() {
    byte[] salt = new byte[16];
    RNG.nextBytes(salt);
    return salt;
  }
}
