// corpus: expect=PG-CRYPTO-003
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.*;
import java.nio.charset.StandardCharsets;

public class Sample {
  GCMParameterSpec spec() { return new GCMParameterSpec(128, "fixed-nonce".getBytes()); }
}
