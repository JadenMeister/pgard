// corpus: expect=PG-CRYPTO-001
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.*;
import java.nio.charset.StandardCharsets;

public class Sample {
  byte[] hash(String password) throws Exception {
    return MessageDigest.getInstance(org.apache.commons.codec.digest.MessageDigestAlgorithms.MD5).digest(password.getBytes());
  }
}
