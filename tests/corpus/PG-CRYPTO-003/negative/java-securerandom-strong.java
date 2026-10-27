// corpus: expect=none
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.*;
import java.nio.charset.StandardCharsets;

public class Sample {
  byte[] nonce() throws Exception {
    byte[] n = new byte[12];
    SecureRandom.getInstanceStrong().nextBytes(n);
    return n;
  }
}
