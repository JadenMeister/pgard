// corpus: expect=low
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;

class AuthController {
  void login(HttpServletResponse resp, String id) {
    Cookie cookie = new Cookie("sessionId", id);
    harden(cookie);
    resp.addCookie(cookie);
  }

  private void harden(Cookie cookie) {
    cookie.setHttpOnly(true);
    cookie.setSecure(true);
  }
}
