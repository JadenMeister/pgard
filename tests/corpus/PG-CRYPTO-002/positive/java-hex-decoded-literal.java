// corpus: expect=PG-CRYPTO-002
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.*;
import java.nio.charset.StandardCharsets;

public class Sample {
  SecretKey key() throws Exception {
    return new SecretKeySpec(org.apache.commons.codec.binary.Hex.decodeHex("00112233445566778899aabbccddeeff"), "AES");
  }
}
