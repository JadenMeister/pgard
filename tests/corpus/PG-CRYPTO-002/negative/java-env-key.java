// corpus: expect=none
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.*;
import java.nio.charset.StandardCharsets;

public class Sample {
  SecretKey key() { return new SecretKeySpec(System.getenv("APP_KEY").getBytes(), "AES"); }
}
