// corpus: expect=none
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;

class AuthController {
  void login(HttpServletResponse res, String token) {
    if (token == null) {
      return;
    }
    Cookie cookie = new Cookie("session", token);
    cookie.setHttpOnly(true);
    cookie.setSecure(true);
    res.addCookie(cookie);
  }
}
