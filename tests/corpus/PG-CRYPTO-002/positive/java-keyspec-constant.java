// corpus: expect=PG-CRYPTO-002
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.*;
import java.nio.charset.StandardCharsets;

public class Sample {
  private static final String KEY = "constant-key-material";
  SecretKey key() { return new SecretKeySpec(KEY.getBytes(StandardCharsets.UTF_8), "AES"); }
}
