// corpus: expect=PG-CRYPTO-002
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.*;
import java.nio.charset.StandardCharsets;

public class Sample {
  Object spec(byte[] salt) { return new PBEKeySpec("literal-passphrase-value".toCharArray(), salt, 10000, 256); }
}
