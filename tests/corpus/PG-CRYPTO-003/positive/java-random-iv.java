// corpus: expect=PG-CRYPTO-003
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.*;
import java.nio.charset.StandardCharsets;

public class Sample {
  IvParameterSpec iv() {
    byte[] b = new byte[16];
    new Random().nextBytes(b);
    return new IvParameterSpec(b);
  }
}
