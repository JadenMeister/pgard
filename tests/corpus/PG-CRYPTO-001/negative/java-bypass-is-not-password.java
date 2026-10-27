// corpus: expect=none
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.*;
import java.nio.charset.StandardCharsets;

public class Sample {
  byte[] hash(String bypassToken) throws Exception {
    return MessageDigest.getInstance("MD5").digest(bypassToken.getBytes());
  }
}
