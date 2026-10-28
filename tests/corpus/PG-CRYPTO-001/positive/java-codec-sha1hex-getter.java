// corpus: expect=PG-CRYPTO-001
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.*;
import java.nio.charset.StandardCharsets;

public class Sample {
  String hash(User user) {
    return org.apache.commons.codec.digest.DigestUtils.sha1Hex(user.getPassword());
  }
}
