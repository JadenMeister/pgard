// corpus: expect=low
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.*;
import java.nio.charset.StandardCharsets;

public class Sample {
  SecretKey key() {
    String material = "dev-only-key-material";
    if (System.getenv("APP_KEY") != null) material = System.getenv("APP_KEY");
    return new SecretKeySpec(material.getBytes(), "AES");
  }
}
