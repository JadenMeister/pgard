// corpus: expect=PG-CRYPTO-002
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.*;
import java.nio.charset.StandardCharsets;

public class Sample {
  Object parse(String jwt) {
    return io.jsonwebtoken.Jwts.parser().setSigningKey("parser-literal-secret").parseClaimsJws(jwt);
  }
}
