// corpus: expect=none
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.*;
import java.nio.charset.StandardCharsets;

public class Sample {
  byte[] hash(String algorithm, String password) throws Exception {
    return MessageDigest.getInstance(algorithm).digest(password.getBytes());
  }
}
