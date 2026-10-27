// corpus: expect=PG-CRYPTO-002
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.*;
import java.nio.charset.StandardCharsets;

public class Sample {
  SecretKey key() {
    String material = "local-key-material-16";
    return new SecretKeySpec(material.getBytes(), "AES");
  }
}
