// corpus: expect=PG-AUTH-001
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.*;
import java.nio.charset.StandardCharsets;

public class Sample {
  void signup(SignupRequest dto, org.springframework.jdbc.core.JdbcTemplate jdbcTemplate) {
    jdbcTemplate.update("INSERT INTO users (email, password) VALUES (?, ?)", dto.getEmail(), dto.getPassword());
  }
}
