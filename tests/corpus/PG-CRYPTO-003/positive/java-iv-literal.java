// corpus: expect=PG-CRYPTO-003
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.*;
import java.nio.charset.StandardCharsets;

public class Sample {
  IvParameterSpec iv() { return new IvParameterSpec("1234567890123456".getBytes()); }
}
