// corpus: expect=none
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;

class AuthController {
  void login(HttpServletResponse resp, String id) {
    Cookie cookie = new Cookie("sid", id);
    cookie.setAttribute("HttpOnly", "true");
    cookie.setAttribute("Secure", "true");
    resp.addCookie(cookie);
  }
}
