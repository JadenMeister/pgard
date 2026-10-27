// corpus: expect=none
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.*;
import java.nio.charset.StandardCharsets;

public class Sample {
  Object algorithm(java.security.interfaces.RSAPublicKey pub, java.security.interfaces.RSAPrivateKey priv) {
    return com.auth0.jwt.algorithms.Algorithm.RSA256(pub, priv);
  }
}
