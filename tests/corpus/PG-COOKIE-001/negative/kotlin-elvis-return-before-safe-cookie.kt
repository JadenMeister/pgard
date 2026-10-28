// corpus: expect=none
import jakarta.servlet.http.Cookie
import jakarta.servlet.http.HttpServletResponse

class AuthController {
  fun login(res: HttpServletResponse, token: String?) {
    val value = token ?: return
    val cookie = Cookie("session", value)
    cookie.isHttpOnly = true
    cookie.secure = true
    res.addCookie(cookie)
  }
}
