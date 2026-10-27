// corpus: expect=none
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.*;
import java.nio.charset.StandardCharsets;

public class Sample {
  Cipher cipher() throws Exception { return Cipher.getInstance("ChaCha20-Poly1305"); }
}
