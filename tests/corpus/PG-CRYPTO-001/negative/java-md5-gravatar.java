// corpus: expect=none
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.*;
import java.nio.charset.StandardCharsets;

public class Sample {
  String avatar(String email) throws Exception {
    byte[] d = MessageDigest.getInstance("MD5").digest(email.trim().toLowerCase().getBytes());
    return "https://www.gravatar.com/avatar/" + Arrays.toString(d);
  }
}
