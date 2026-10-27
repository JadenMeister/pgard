// corpus: expect=none
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.*;
import java.nio.charset.StandardCharsets;
import org.springframework.beans.factory.annotation.Value;

public class Sample {
  @Value("${hash.algorithm}") String alg;
  byte[] hash(String password) throws Exception {
    return MessageDigest.getInstance(alg).digest(password.getBytes());
  }
}
