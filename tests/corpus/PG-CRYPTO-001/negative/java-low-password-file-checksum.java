// corpus: expect=low
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.*;
import java.nio.charset.StandardCharsets;

public class Sample {
  byte[] passwordFileChecksum(byte[] content) throws Exception {
    return MessageDigest.getInstance("MD5").digest(content);
  }
}
