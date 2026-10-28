// corpus: expect=none
import org.springframework.session.web.http.DefaultCookieSerializer;

class SessionConfig {
  DefaultCookieSerializer serializer() {
    DefaultCookieSerializer serializer = new DefaultCookieSerializer();
    serializer.setUseHttpOnlyCookie(true);
    serializer.setUseSecureCookie(true);
    return serializer;
  }
}
