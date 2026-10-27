// corpus: expect=PG-CRYPTO-002
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.*;
import java.nio.charset.StandardCharsets;

public class Sample {
  private static final byte[] KEY = "bytes-constant-key".getBytes();
  SecretKey key() { return new SecretKeySpec(KEY, "AES"); }
}
