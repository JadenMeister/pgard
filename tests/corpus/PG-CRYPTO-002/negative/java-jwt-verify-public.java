// corpus: expect=none
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.*;
import java.nio.charset.StandardCharsets;

public class Sample {
  Object verifier(java.security.interfaces.RSAPublicKey pub) {
    return com.auth0.jwt.JWT.require(com.auth0.jwt.algorithms.Algorithm.RSA256(pub, null)).build();
  }
}
