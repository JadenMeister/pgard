// corpus: expect=PG-CRYPTO-002
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.*;
import java.nio.charset.StandardCharsets;

public class Sample {
  Key key() {
    String s = System.getProperty("jwt.secret", "default-property-secret-0123456789abcdef");
    return io.jsonwebtoken.security.Keys.hmacShaKeyFor(s.getBytes());
  }
}
