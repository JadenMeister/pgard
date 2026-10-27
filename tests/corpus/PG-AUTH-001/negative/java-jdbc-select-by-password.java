// corpus: expect=none
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.*;
import java.nio.charset.StandardCharsets;
import org.springframework.web.bind.annotation.*;

public class Sample {
  List<Map<String, Object>> find(@RequestParam String password, org.springframework.jdbc.core.JdbcTemplate jdbcTemplate) {
    return jdbcTemplate.queryForList("SELECT email FROM legacy_users WHERE password = ?", password);
  }
}
