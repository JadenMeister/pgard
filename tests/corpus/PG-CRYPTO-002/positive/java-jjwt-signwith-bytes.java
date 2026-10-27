// corpus: expect=PG-CRYPTO-002
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.*;
import java.nio.charset.StandardCharsets;

public class Sample {
  String token() {
    return io.jsonwebtoken.Jwts.builder().setSubject("a")
        .signWith(io.jsonwebtoken.SignatureAlgorithm.HS256, "jjwt-bytes-secret".getBytes()).compact();
  }
}
