// corpus: expect=PG-CRYPTO-001
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.*;
import java.nio.charset.StandardCharsets;

public class Sample {
  byte[] hash(User user) throws Exception {
    return MessageDigest.getInstance("SHA-1").digest(user.getPassword().getBytes());
  }
}
