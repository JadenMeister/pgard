// corpus: expect=none
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.*;
import java.nio.charset.StandardCharsets;

public class Sample {
  private static final String SECRET_HEADER = "X-Secret-Token";
  String read(javax.servlet.http.HttpServletRequest request) { return request.getHeader(SECRET_HEADER); }
}
