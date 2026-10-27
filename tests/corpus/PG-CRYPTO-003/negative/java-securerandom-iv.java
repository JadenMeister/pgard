// corpus: expect=none
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.*;
import java.nio.charset.StandardCharsets;

public class Sample {
  GCMParameterSpec spec() {
    byte[] iv = new byte[12];
    new SecureRandom().nextBytes(iv);
    return new GCMParameterSpec(128, iv);
  }
}
