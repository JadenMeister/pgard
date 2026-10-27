// corpus: expect=none
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.*;
import java.nio.charset.StandardCharsets;

public class Sample {
  byte[] blob(byte[] content) throws Exception {
    MessageDigest md = MessageDigest.getInstance("SHA-1");
    md.update(("blob " + content.length + "\0").getBytes());
    md.update(content);
    return md.digest();
  }
}
