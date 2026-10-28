// corpus: expect=none
import io.ktor.http.Cookie;

class Client {
  Cookie make(String id) {
    return new Cookie("sessionId", id);
  }
}
