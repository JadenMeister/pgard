// corpus: expect=none
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.*;
import java.nio.charset.StandardCharsets;

public class Sample {
  String cacheKey(String url) throws Exception {
    return Arrays.toString(MessageDigest.getInstance("MD5").digest(url.getBytes()));
  }
}
