// corpus: expect=none
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.*;
import java.nio.charset.StandardCharsets;

public class Sample {
  Key key(Properties props) {
    return io.jsonwebtoken.security.Keys.hmacShaKeyFor(props.getProperty("jwt.secret").getBytes());
  }
}
