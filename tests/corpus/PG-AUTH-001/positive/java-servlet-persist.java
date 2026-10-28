// corpus: expect=PG-AUTH-001
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.*;
import java.nio.charset.StandardCharsets;

public class Sample {
  void signup(javax.servlet.http.HttpServletRequest request, javax.persistence.EntityManager em) {
    String pw = request.getParameter("password");
    User user = new User();
    user.setPassword(pw);
    em.persist(user);
  }
}
