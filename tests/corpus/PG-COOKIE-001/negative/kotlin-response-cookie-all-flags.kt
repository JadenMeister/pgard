// corpus: expect=none
import org.springframework.http.HttpHeaders
import org.springframework.http.ResponseCookie
import org.springframework.http.ResponseEntity

class AuthController {
  fun login(id: String): ResponseEntity<Void> {
    val cookie = ResponseCookie.from("session", id).httpOnly(true).secure(true).sameSite("Strict").build()
    return ResponseEntity.ok().header(HttpHeaders.SET_COOKIE, cookie.toString()).build()
  }
}
