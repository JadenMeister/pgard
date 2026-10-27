// corpus: expect=none
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.*;
import java.nio.charset.StandardCharsets;

public class Sample {
  private static final String KEY = "shadowed-constant-material";
  SecretKey key(String KEY) { return new SecretKeySpec(KEY.getBytes(), "AES"); }
}
