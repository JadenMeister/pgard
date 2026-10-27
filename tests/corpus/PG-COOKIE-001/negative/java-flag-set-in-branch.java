// corpus: expect=low
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;

class AuthController {
  void login(HttpServletResponse resp, String id) {
    Cookie cookie = new Cookie("sid", id);
    cookie.setHttpOnly(true);
    if (id.length() > 3) {
      cookie.setSecure(true);
    }
    resp.addCookie(cookie);
  }
}
