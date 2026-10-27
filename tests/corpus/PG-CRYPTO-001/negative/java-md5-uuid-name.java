// corpus: expect=none
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.*;
import java.nio.charset.StandardCharsets;

public class Sample {
  UUID id(String name) {
    return UUID.nameUUIDFromBytes(name.getBytes());
  }
}
