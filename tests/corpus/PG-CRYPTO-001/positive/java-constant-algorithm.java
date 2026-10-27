// corpus: expect=PG-CRYPTO-001
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.*;
import java.nio.charset.StandardCharsets;

public class Sample {
  private static final String ALGO = "MD5";
  byte[] hash(String password) throws Exception {
    return MessageDigest.getInstance(ALGO).digest(password.getBytes());
  }
}
