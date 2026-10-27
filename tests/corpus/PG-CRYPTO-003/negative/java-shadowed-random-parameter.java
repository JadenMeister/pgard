// corpus: expect=none
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.*;
import java.nio.charset.StandardCharsets;

public class Sample {
  private static final Random RND = new Random();
  byte[] token(SecureRandom RND) {
    byte[] token = new byte[16];
    RND.nextBytes(token);
    return token;
  }
}
