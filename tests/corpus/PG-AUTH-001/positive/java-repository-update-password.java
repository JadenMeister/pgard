// corpus: expect=PG-AUTH-001
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.*;
import java.nio.charset.StandardCharsets;
import org.springframework.web.bind.annotation.*;

public class Sample {
  void change(@RequestParam String newPassword, long id, UserRepository userRepository) {
    userRepository.updatePassword(id, newPassword);
  }
}
