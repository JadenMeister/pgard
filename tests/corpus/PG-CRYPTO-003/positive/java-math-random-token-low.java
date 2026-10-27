// corpus: expect=PG-CRYPTO-003
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.*;
import java.nio.charset.StandardCharsets;

public class Sample {
  String make() {
    String token = Long.toHexString((long) (Math.random() * 1e15));
    return token;
  }
}
