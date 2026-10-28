// corpus: expect=none
import jakarta.servlet.http.Cookie
import jakarta.servlet.http.HttpServletResponse

class AuthController {
  fun login(resp: HttpServletResponse, id: String) {
    val cookie = Cookie("authToken", id)
    cookie.isHttpOnly = true
    cookie.secure = true
    resp.addCookie(cookie)
  }
}
