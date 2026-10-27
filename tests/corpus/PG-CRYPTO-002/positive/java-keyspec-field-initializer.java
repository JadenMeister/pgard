// corpus: expect=PG-CRYPTO-002
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.*;
import java.nio.charset.StandardCharsets;

public class Sample {
  private final SecretKeySpec spec = new SecretKeySpec("field-initializer-key".getBytes(), "AES");
}
