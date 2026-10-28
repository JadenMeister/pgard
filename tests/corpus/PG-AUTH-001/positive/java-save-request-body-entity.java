// corpus: expect=PG-AUTH-001
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.*;
import java.nio.charset.StandardCharsets;
import org.springframework.web.bind.annotation.*;

public class Sample {
  static class Account { String email; String password; }
  void signup(@RequestBody Account account, AccountRepository accountRepository) {
    accountRepository.save(account);
  }
}
