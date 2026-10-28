// corpus: expect=PG-COOKIE-001
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;

class AuthController {
  void login(HttpServletResponse resp, String id) {
    Cookie cookie = new Cookie("remember-me", id);
    cookie.setHttpOnly(true);
    cookie.setMaxAge(3600);
    resp.addCookie(cookie);
  }
}
