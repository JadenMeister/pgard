// corpus: expect=PG-COOKIE-001
import jakarta.servlet.http.Cookie
import jakarta.servlet.http.HttpServletResponse

class AuthController {
  fun login(resp: HttpServletResponse, id: String) {
    resp.addCookie(Cookie("authToken", id).apply {
      secure = true
      path = "/"
    })
  }
}
