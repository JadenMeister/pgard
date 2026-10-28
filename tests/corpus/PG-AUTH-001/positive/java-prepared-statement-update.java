// corpus: expect=PG-AUTH-001
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.*;
import java.nio.charset.StandardCharsets;
import org.springframework.web.bind.annotation.*;

public class Sample {
  void change(@RequestParam String password, long id, java.sql.Connection connection) throws Exception {
    java.sql.PreparedStatement ps = connection.prepareStatement("UPDATE users SET password = ? WHERE id = ?");
    ps.setString(1, password);
    ps.setLong(2, id);
    ps.executeUpdate();
  }
}
