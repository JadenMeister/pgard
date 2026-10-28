// corpus: expect=PG-COOKIE-001
import jakarta.servlet.http.Cookie
import jakarta.servlet.http.HttpServletResponse

class AuthController {
  fun login(resp: HttpServletResponse, id: String) {
    val cookie = Cookie("sid", id).apply { isHttpOnly = true }
    resp.addCookie(cookie)
  }
}
