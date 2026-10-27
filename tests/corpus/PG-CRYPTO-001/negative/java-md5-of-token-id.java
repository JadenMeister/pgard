// corpus: expect=none
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.*;
import java.nio.charset.StandardCharsets;

public class Sample {
  byte[] fingerprint(String clientId) throws Exception {
    return MessageDigest.getInstance("MD5").digest(clientId.getBytes());
  }
}
