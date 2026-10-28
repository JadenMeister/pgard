// corpus: expect=PG-COOKIE-001
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;

class AuthController {
  void login(HttpServletResponse resp, String id, boolean logout) {
    Cookie cookie = new Cookie("sessionId", id);
    if (logout) {
      cookie.setMaxAge(0);
    }
    resp.addCookie(cookie);
  }
}
