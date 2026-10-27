// corpus: expect=PG-CRYPTO-001
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.*;
import java.nio.charset.StandardCharsets;

public class Sample {
  String hash(String password) {
    return com.google.common.hash.Hashing.sha1().hashBytes(password.getBytes()).toString();
  }
}
