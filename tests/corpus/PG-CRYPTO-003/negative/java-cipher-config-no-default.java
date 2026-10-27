// corpus: expect=none
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.*;
import java.nio.charset.StandardCharsets;
import org.springframework.beans.factory.annotation.Value;

public class Sample {
  @Value("${crypto.cipher}") String alg;
  Cipher cipher() throws Exception { return Cipher.getInstance(alg); }
}
