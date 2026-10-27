// corpus: expect=none
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.*;
import java.nio.charset.StandardCharsets;

public class Sample {
  long backoff() { return 100 + ThreadLocalRandom.current().nextLong(50); }
}
