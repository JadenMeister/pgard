// corpus: expect=PG-CRYPTO-001
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.*;
import java.nio.charset.StandardCharsets;

public class Sample {
  byte[] hash(String password) throws Exception {
    String algorithm = "SHA-1";
    MessageDigest md = MessageDigest.getInstance(algorithm);
    md.update(password.getBytes());
    return md.digest();
  }
}
