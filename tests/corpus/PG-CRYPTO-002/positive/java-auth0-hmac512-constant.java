// corpus: expect=PG-CRYPTO-002
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.*;
import java.nio.charset.StandardCharsets;

public class Sample {
  private static final String SECRET = "auth0-constant-secret";
  Object algorithm() { return com.auth0.jwt.algorithms.Algorithm.HMAC512(SECRET); }
}
