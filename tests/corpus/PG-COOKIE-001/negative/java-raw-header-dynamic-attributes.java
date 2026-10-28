// corpus: expect=low
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;

class AuthController {
  void login(HttpServletResponse resp, String id, boolean logout) {
    resp.addHeader("Set-Cookie", "sessionId=" + id + "; Path=/" + attributes());
  }
}
