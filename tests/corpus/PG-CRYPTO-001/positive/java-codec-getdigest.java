// corpus: expect=PG-CRYPTO-001
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.*;
import java.nio.charset.StandardCharsets;

public class Sample {
  byte[] hash(String password) {
    return org.apache.commons.codec.digest.DigestUtils.getDigest("MD5").digest(password.getBytes());
  }
}
