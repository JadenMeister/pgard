// corpus: expect=none
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.*;
import java.nio.charset.StandardCharsets;

public class Sample {
  Key key(java.security.KeyStore store, char[] pass) throws Exception { return store.getKey("alias", pass); }
}
