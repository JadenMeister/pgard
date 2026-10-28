// corpus: expect=none
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;

class AuthController {
  void login(HttpServletResponse resp, String id) {
    Cookie cookie = new Cookie("sessionId", id);
    cookie.setHttpOnly(true);
    cookie.setSecure(true);
    resp.addCookie(cookie);
  }
}
