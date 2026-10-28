// corpus: expect=none
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;

class AuthController {
  void login(HttpServletResponse resp, String id) {
    Cookie cookie = new Cookie("lang", "ko");
    cookie.setMaxAge(31536000);
    resp.addCookie(cookie);
  }
}
