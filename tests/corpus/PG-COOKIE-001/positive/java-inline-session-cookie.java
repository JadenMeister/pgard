// corpus: expect=PG-COOKIE-001
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;

class AuthController {
  void login(HttpServletResponse resp, String id) {
    resp.addCookie(new Cookie("sessionId", id));
  }
}
