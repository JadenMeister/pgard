// corpus: expect=PG-CRYPTO-002
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.*;
import java.nio.charset.StandardCharsets;

public class Sample {
  Object algorithm() { return com.auth0.jwt.algorithms.Algorithm.HMAC256("auth0-literal-secret"); }
}
