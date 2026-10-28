// corpus: expect=low
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;

class AuthController {
  void login(HttpServletResponse resp, String id) {
    boolean secureFlag = id.startsWith("s");
    Cookie cookie = new Cookie("sid", id);
    cookie.setHttpOnly(true);
    cookie.setSecure(secureFlag);
    resp.addCookie(cookie);
  }
}
