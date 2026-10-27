// corpus: expect=low
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.*;
import java.nio.charset.StandardCharsets;

public class Sample {
  Cipher cipher(Properties props) throws Exception {
    return Cipher.getInstance(props.getProperty("legacy.cipher", "DES"));
  }
}
