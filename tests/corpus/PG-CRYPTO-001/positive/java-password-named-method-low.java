// corpus: expect=PG-CRYPTO-001
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.*;
import java.nio.charset.StandardCharsets;

public class Sample {
  byte[] hashPassword(byte[] raw) throws Exception {
    return MessageDigest.getInstance("MD5").digest(raw);
  }
}
