// corpus: expect=PG-AUTH-001
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.*;
import java.nio.charset.StandardCharsets;

public class Sample {
  void signup(SignupRequest dto, java.sql.Connection connection) throws Exception {
    java.sql.PreparedStatement ps = connection.prepareStatement("INSERT INTO users (email, password) VALUES (?, ?)");
    ps.setString(1, dto.getEmail());
    ps.setString(2, dto.getPassword());
    ps.executeUpdate();
  }
}
