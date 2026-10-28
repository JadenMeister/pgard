// corpus: expect=low
import jakarta.servlet.http.Cookie
import jakarta.servlet.http.HttpServletResponse

class AuthController {
  fun login(resp: HttpServletResponse, id: String, flag: Boolean) {
    val cookie = Cookie("sid", id)
    cookie.isHttpOnly = flag
    cookie.secure = true
    resp.addCookie(cookie)
  }
}
