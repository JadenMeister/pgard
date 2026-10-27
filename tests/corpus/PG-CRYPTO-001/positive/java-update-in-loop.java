// corpus: expect=PG-CRYPTO-001
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.*;
import java.nio.charset.StandardCharsets;

public class Sample {
  byte[] hash(List<String> passwords) throws Exception {
    MessageDigest md = MessageDigest.getInstance("MD5");
    for (String password : passwords) md.update(password.getBytes());
    return md.digest();
  }
}
