// corpus: expect=PG-CRYPTO-001
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.*;
import java.nio.charset.StandardCharsets;

public class Sample {
  String hash(String password) throws Exception {
    MessageDigest md = MessageDigest.getInstance("MD5");
    md.update(password.getBytes(StandardCharsets.UTF_8));
    return Arrays.toString(md.digest());
  }
}
