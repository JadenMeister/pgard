// corpus: expect=none
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.*;
import java.nio.charset.StandardCharsets;
import org.springframework.web.bind.annotation.*;

public class Sample {
  void signup(@RequestBody SignupRequest dto, UserRepository userRepository, PasswordEncoder passwordEncoder) {
    User user = new User();
    user.setPassword(passwordEncoder.encode(dto.getPassword()));
    userRepository.save(user);
  }
}
