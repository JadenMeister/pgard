// corpus: expect=PG-CRYPTO-003
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.*;
import java.nio.charset.StandardCharsets;

public class Sample {
  String reset() {
    String resetToken = String.valueOf(new Random().nextInt());
    return resetToken;
  }
}
