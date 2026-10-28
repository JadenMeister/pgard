// corpus: expect=none
import javax.servlet.http.Cookie;

class Fixture {
  int sizeOf(String id) {
    Cookie unused = new Cookie("sessionId", id);
    return id.length();
  }
}
