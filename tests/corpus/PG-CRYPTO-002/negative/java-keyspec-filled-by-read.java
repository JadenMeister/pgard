// corpus: expect=none
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.*;
import java.nio.charset.StandardCharsets;

public class Sample {
  SecretKey key(java.io.InputStream in) throws Exception {
    byte[] b = new byte[32];
    in.read(b);
    return new SecretKeySpec(b, "AES");
  }
}
