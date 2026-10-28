// corpus: expect=PG-COOKIE-001
import org.springframework.session.web.http.DefaultCookieSerializer;

class SessionConfig {
  DefaultCookieSerializer serializer() {
    DefaultCookieSerializer serializer = new DefaultCookieSerializer();
    serializer.setUseSecureCookie(false);
    return serializer;
  }
}
