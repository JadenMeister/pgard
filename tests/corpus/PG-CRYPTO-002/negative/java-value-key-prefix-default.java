// corpus: expect=none
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.*;
import java.nio.charset.StandardCharsets;
import org.springframework.beans.factory.annotation.Value;

public class Sample {
  @Value("${cache.key-prefix:app}") String prefix;
  @Value("${jwt.public-key:classpath:public.pem}") String publicKey;
  @Value("${jwt.header:Authorization}") String header;
}
