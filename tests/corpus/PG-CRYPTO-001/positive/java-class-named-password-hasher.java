// corpus: expect=PG-CRYPTO-001
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.*;
import java.nio.charset.StandardCharsets;

public class PasswordHasher {
  byte[] run(byte[] data) throws Exception {
    return MessageDigest.getInstance("SHA-1").digest(data);
  }
}
