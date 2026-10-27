// corpus: expect=PG-CRYPTO-003
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.*;
import java.nio.charset.StandardCharsets;

public class Sample {
  private static final byte[] IV = "fixed-iv-constant".getBytes();
  IvParameterSpec iv() { return new IvParameterSpec(IV); }
}
