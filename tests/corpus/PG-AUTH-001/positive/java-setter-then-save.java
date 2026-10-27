// corpus: expect=PG-AUTH-001
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.*;
import java.nio.charset.StandardCharsets;
import org.springframework.web.bind.annotation.*;

public class Sample {
  void signup(@RequestBody SignupRequest dto, UserRepository userRepository) {
    User user = new User();
    user.setEmail(dto.getEmail());
    user.setPassword(dto.getPassword());
    userRepository.save(user);
  }
}
