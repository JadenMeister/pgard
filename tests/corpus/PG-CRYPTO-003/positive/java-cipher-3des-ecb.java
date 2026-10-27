// corpus: expect=PG-CRYPTO-003
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.*;
import java.nio.charset.StandardCharsets;

public class Sample {
  Cipher cipher() throws Exception { return Cipher.getInstance("DESede/ECB/PKCS5Padding"); }
}
