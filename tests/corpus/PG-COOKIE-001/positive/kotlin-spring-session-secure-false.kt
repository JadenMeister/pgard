// corpus: expect=PG-COOKIE-001
import org.springframework.session.web.http.DefaultCookieSerializer

class SessionConfig {
  fun serializer(): DefaultCookieSerializer = DefaultCookieSerializer().apply {
    setUseSecureCookie(false)
  }
}
