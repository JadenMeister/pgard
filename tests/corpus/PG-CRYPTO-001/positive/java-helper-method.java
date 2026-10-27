// corpus: expect=PG-CRYPTO-001
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.*;
import java.nio.charset.StandardCharsets;

public class Sample {
  private static String md5(String input) throws Exception {
    return new String(MessageDigest.getInstance("MD5").digest(input.getBytes()));
  }
  String store(String password) throws Exception {
    return md5(password);
  }
}
