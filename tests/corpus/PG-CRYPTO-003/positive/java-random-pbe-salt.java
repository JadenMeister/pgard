// corpus: expect=PG-CRYPTO-003
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.*;
import java.nio.charset.StandardCharsets;

public class Sample {
  Object spec(char[] pw) {
    byte[] salt = new byte[16];
    new Random().nextBytes(salt);
    return new PBEKeySpec(pw, salt, 10000, 256);
  }
}
