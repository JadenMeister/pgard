// corpus: expect=none
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.*;
import java.nio.charset.StandardCharsets;

public class Sample {
  String loadSecret() { return System.getenv("JWT_SECRET"); }
  Object algorithm() { return com.auth0.jwt.algorithms.Algorithm.HMAC256(loadSecret()); }
}
