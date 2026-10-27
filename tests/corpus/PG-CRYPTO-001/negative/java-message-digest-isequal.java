// corpus: expect=none
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.*;
import java.nio.charset.StandardCharsets;

public class Sample {
  boolean same(byte[] a, byte[] b) {
    return MessageDigest.isEqual(a, b);
  }
}
