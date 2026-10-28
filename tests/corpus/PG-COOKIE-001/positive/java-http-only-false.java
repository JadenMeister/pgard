// corpus: expect=PG-COOKIE-001
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;

class AuthController {
  void login(HttpServletResponse resp, String id) {
    Cookie cookie = new Cookie("auth", id);
    cookie.setHttpOnly(false);
    cookie.setSecure(true);
    resp.addCookie(cookie);
  }
}
