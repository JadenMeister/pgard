// corpus: expect=PG-AUTH-001
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.*;
import java.nio.charset.StandardCharsets;

public class Sample {
  void signup(SignupRequest dto, org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate namedJdbc) {
    namedJdbc.update("INSERT INTO users (email, password) VALUES (:email, :password)",
        new org.springframework.jdbc.core.namedparam.MapSqlParameterSource()
            .addValue("email", dto.getEmail()).addValue("password", dto.getPassword()));
  }
}
