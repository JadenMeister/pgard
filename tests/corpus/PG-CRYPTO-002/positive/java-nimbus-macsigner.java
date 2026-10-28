// corpus: expect=PG-CRYPTO-002
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.*;
import java.nio.charset.StandardCharsets;

public class Sample {
  Object signer() throws Exception {
    return new com.nimbusds.jose.crypto.MACSigner("nimbus-literal-secret-0123456789abcdef");
  }
}
