// corpus: expect=low
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;

class CookieFactory {
  Cookie sessionCookie(String id) {
    Cookie cookie = new Cookie("sessionId", id);
    return cookie;
  }
}
