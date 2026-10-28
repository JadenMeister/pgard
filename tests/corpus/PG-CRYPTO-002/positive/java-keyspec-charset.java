// corpus: expect=PG-CRYPTO-002
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.*;
import java.nio.charset.StandardCharsets;

public class Sample {
  SecretKey key() { return new SecretKeySpec("hardcoded-aes-key-0123".getBytes(StandardCharsets.UTF_8), "AES"); }
}
