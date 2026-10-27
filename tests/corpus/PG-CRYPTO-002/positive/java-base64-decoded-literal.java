// corpus: expect=PG-CRYPTO-002
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.*;
import java.nio.charset.StandardCharsets;

public class Sample {
  SecretKey key() {
    return new SecretKeySpec(Base64.getDecoder().decode("c2VjcmV0LWtleS1saXRlcmFs"), "AES");
  }
}
