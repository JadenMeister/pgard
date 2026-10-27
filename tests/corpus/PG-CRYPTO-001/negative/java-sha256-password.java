// corpus: expect=none
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.*;
import java.nio.charset.StandardCharsets;

public class Sample {
  byte[] hash(String password) throws Exception {
    return MessageDigest.getInstance("SHA-256").digest(password.getBytes());
  }
}
