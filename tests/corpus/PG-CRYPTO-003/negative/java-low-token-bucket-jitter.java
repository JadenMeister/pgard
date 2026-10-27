// corpus: expect=low
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.*;
import java.nio.charset.StandardCharsets;

public class Sample {
  int jitter() {
    int tokenBucketDelay = new Random().nextInt(50);
    return tokenBucketDelay;
  }
}
