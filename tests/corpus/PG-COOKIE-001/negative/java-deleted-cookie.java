// corpus: expect=none
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;

class AuthController {
  void login(HttpServletResponse resp, String id) {
    Cookie cookie = new Cookie("sessionId", null);
    cookie.setMaxAge(0);
    resp.addCookie(cookie);
  }
}
