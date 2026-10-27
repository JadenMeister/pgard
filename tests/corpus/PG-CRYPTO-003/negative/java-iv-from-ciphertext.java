// corpus: expect=none
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.*;
import java.nio.charset.StandardCharsets;

public class Sample {
  IvParameterSpec iv(byte[] data) { return new IvParameterSpec(Arrays.copyOfRange(data, 0, 16)); }
}
