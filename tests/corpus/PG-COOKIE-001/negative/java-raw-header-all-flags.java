// corpus: expect=none
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;

class AuthController {
  void login(HttpServletResponse resp, String id) {
    resp.addHeader("Set-Cookie", "sessionId=" + id + "; Path=/; HttpOnly; Secure; SameSite=Lax");
  }
}
