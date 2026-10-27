// corpus: expect=none
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.*;
import java.nio.charset.StandardCharsets;

public class Sample {
  byte[] checksum(byte[] content) throws Exception {
    MessageDigest md = MessageDigest.getInstance("SHA-1");
    md.update(content);
    return md.digest();
  }
}
