// corpus: expect=none
import jakarta.servlet.http.Cookie
import jakarta.servlet.http.HttpServletResponse

class AuthController {
  fun login(resp: HttpServletResponse, id: String) {
    resp.addCookie(Cookie("ui-theme", "dark"))
  }
}
