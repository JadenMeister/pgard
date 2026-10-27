// corpus: expect=none
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.*;
import java.nio.charset.StandardCharsets;

public class Sample {
  void prepare(SignupRequest dto) {
    User user = new User();
    user.setPassword(dto.getPassword());
  }
}
