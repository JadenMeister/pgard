// corpus: expect=PG-CRYPTO-001
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.*;
import java.nio.charset.StandardCharsets;

public class Sample {
  byte[] hash(String pwd) throws Exception {
    return MessageDigest.getInstance("SHA").digest(pwd.getBytes());
  }
}
