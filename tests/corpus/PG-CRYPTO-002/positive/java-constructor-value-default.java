// corpus: expect=PG-CRYPTO-002
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.*;
import java.nio.charset.StandardCharsets;
import org.springframework.beans.factory.annotation.Value;

public class Sample {
  private final String signingKey;
  public Sample(@Value("${app.signing-key:dev-signing-key}") String signingKey) { this.signingKey = signingKey; }
}
