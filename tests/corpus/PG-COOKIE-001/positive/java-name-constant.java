// corpus: expect=PG-COOKIE-001
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;

class AuthController {
  static final String SESSION_COOKIE = "app_session";

  void login(HttpServletResponse resp, String id) {
    Cookie cookie = new Cookie(SESSION_COOKIE, id);
    resp.addCookie(cookie);
  }
}
