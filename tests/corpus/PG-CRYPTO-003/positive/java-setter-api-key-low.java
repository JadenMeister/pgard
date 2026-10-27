// corpus: expect=PG-CRYPTO-003
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.*;
import java.nio.charset.StandardCharsets;

public class Sample {
  void rotate(User user) { user.setApiKey(org.apache.commons.lang3.RandomStringUtils.randomAlphanumeric(32)); }
}
