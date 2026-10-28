// corpus: expect=none
import jakarta.servlet.http.Cookie
import jakarta.servlet.http.HttpServletResponse

class AuthController {
  fun login(resp: HttpServletResponse, id: String) {
    resp.addHeader("Set-Cookie", "session=$id; Path=/; HttpOnly; Secure")
  }
}
