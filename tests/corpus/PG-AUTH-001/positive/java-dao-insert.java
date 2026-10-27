// corpus: expect=PG-AUTH-001
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.*;
import java.nio.charset.StandardCharsets;

public class Sample {
  void signup(RegisterForm form, UserDao userDao) {
    User user = new User();
    user.setPassword(form.getPassword());
    userDao.insert(user);
  }
}
