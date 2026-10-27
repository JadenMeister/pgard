// corpus: expect=none
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.*;
import java.nio.charset.StandardCharsets;

public class Sample {
  IvParameterSpec iv(java.io.InputStream in) throws Exception {
    byte[] b = new byte[16];
    in.read(b);
    return new IvParameterSpec(b);
  }
}
