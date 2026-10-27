// corpus: expect=PG-CRYPTO-002
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.*;
import java.nio.charset.StandardCharsets;

public class Sample {
  Key key() {
    return io.jsonwebtoken.security.Keys.hmacShaKeyFor("hmac-literal-secret-0123456789abcdef".getBytes());
  }
}
