// corpus: expect=none
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.*;
import java.nio.charset.StandardCharsets;

public class Sample {
  String hash(String password) {
    return com.google.common.hash.Hashing.sha256().hashString(password, StandardCharsets.UTF_8).toString();
  }
}
